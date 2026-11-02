<?php

namespace App\Auth;

use App\Auth\Sso\Sso;
use App\Config\Config;
use App\Http\ApiError;
use App\Models\Device;
use App\Models\User;
use App\Support\Dates;
use Throwable;
use UnexpectedValueException;

/**
 * An access token with its refresh token (auth::AuthTokens).
 */
final readonly class AuthTokens
{
    private const int DEFAULT_REFRESH_VALIDITY = 30 * 86_400;

    private const int MOBILE_REFRESH_VALIDITY = 90 * 86_400;

    /**
     * @param  array<string, mixed>  $refreshClaims  RefreshJwtClaims in field order
     */
    private function __construct(
        public array $refreshClaims,
        public LoginClaims $accessClaims,
        public AuthMethod $method,
        private Jwt $jwt,
    ) {}

    /**
     * AuthTokens::new: the default validity, longer refresh tokens for mobile devices.
     */
    public static function new(Device $device, User $user, AuthMethod $method, ?string $clientId, Jwt $jwt): self
    {
        $now = Dates::now()->getTimestamp();

        return new self([
            'nbf' => $now,
            'exp' => $now + ($device->isMobile() ? self::MOBILE_REFRESH_VALIDITY : self::DEFAULT_REFRESH_VALIDITY),
            'iss' => $jwt->issuer(JwtIssuer::Login),
            'sub' => $method->value,
            'device_token' => $device->refresh_token,
            'token' => null,
        ], LoginClaims::default($device, $user, $method, $clientId, $jwt), $method, $jwt);
    }

    /**
     * Tokens with claims made elsewhere, as for SSO sessions.
     *
     * @param  array<string, mixed>  $refreshClaims  RefreshJwtClaims in field order
     */
    public static function withClaims(array $refreshClaims, LoginClaims $accessClaims, AuthMethod $method, Jwt $jwt): self
    {
        return new self($refreshClaims, $accessClaims, $method, $jwt);
    }

    /**
     * auth::refresh_tokens: new tokens for the device of a valid refresh token.
     *
     * @return array{Device, self}
     *
     * @throws ApiError
     */
    public static function refresh(string $refreshToken, ?string $clientId, string $ip, Jwt $jwt, Config $config): array
    {
        try {
            $claims = $jwt->decode($refreshToken, JwtIssuer::Login);
            [$method, $deviceToken] = self::refreshClaims($claims);
        } catch (Throwable $error) {
            logger()->error("Failed to decode refresh_token from {$ip}: {$error->getMessage()}");

            throw ApiError::silent('Invalid refresh token');
        }

        $device = Device::findByRefreshToken($deviceToken) ?? throw ApiError::message('Invalid refresh token');
        // Saved to update updated_at.
        $device->save();

        $user = User::findByUuid($device->user_uuid) ?? throw ApiError::message('Impossible to find user');

        $sso = $config->bool('sso_enabled');
        $tokens = match (true) {
            $method === AuthMethod::Sso && $sso && $config->bool('sso_auth_only_not_session') => self::new($device, $user, $method, $clientId, $jwt),
            $method === AuthMethod::Sso && $sso => (new Sso($config, $jwt))->exchangeRefreshToken($device, $user, $clientId, $claims),
            $method === AuthMethod::Sso => throw ApiError::message('SSO is now disabled, Login again using email and master password'),
            $method === AuthMethod::Password && $sso && $config->bool('sso_only') => throw ApiError::message('SSO is now required, Login again'),
            $method === AuthMethod::Password => self::new($device, $user, $method, $clientId, $jwt),
            default => throw ApiError::message('Invalid auth method, cannot refresh token'),
        };

        return [$device, $tokens];
    }

    public function refreshToken(): string
    {
        return $this->jwt->encode($this->refreshClaims);
    }

    public function accessToken(): string
    {
        return $this->accessClaims->token($this->jwt);
    }

    public function expiresIn(): int
    {
        return $this->accessClaims->expiresIn();
    }

    public function scope(): string
    {
        return $this->method->scope();
    }

    /**
     * Deserializing RefreshJwtClaims: every field with its type.
     *
     * @param  array<string, mixed>  $claims
     * @return array{AuthMethod, string} The method and the device's refresh token
     */
    private static function refreshClaims(array $claims): array
    {
        $token = $claims['token'] ?? null;
        $validToken = $token === null || (is_array($token) && count($token) === 1
            && in_array(array_key_first($token), ['Access', 'Refresh'], true) && is_string(reset($token)));

        if (! is_int($claims['nbf'] ?? null) || ! is_int($claims['exp'] ?? null) || ! is_string($claims['iss'] ?? null)
            || ! is_string($claims['device_token'] ?? null) || ! array_key_exists('token', $claims) || ! $validToken) {
            throw new UnexpectedValueException('Error decoding JWT: Error(Json)');
        }

        $method = AuthMethod::tryFrom(is_string($claims['sub'] ?? null) ? $claims['sub'] : '')
            ?? throw new UnexpectedValueException('Error decoding JWT: Error(Json)');

        return [$method, $claims['device_token']];
    }
}
