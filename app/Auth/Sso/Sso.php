<?php

namespace App\Auth\Sso;

use App\Auth\AuthMethod;
use App\Auth\AuthTokens;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\LoginClaims;
use App\Config\Config;
use App\Http\ApiError;
use App\Models\Device;
use App\Models\SsoAuth;
use App\Models\SsoUser;
use App\Models\User;
use App\Support\Dates;
use App\Support\EscapeDebug;
use stdClass;

/**
 * src/sso.rs: the SSO login between the clients, Vaultwarden and the
 * OpenID provider, and the tokens it ends in. Unless
 * SSO_AUTH_ONLY_NOT_SESSION, the session follows the provider's tokens.
 */
final readonly class Sso
{
    /**
     * auth::BW_EXPIRATION: an access token closer to its end is refreshed.
     */
    private const int BW_EXPIRATION = 300;

    /**
     * auth::DEFAULT_REFRESH_VALIDITY
     */
    private const int DEFAULT_REFRESH_VALIDITY = 30 * 86_400;

    public function __construct(
        private Config $config,
        private Jwt $jwt,
    ) {}

    /**
     * decode_state: the state comes back base64 encoded.
     *
     * @throws ApiError
     */
    public static function decodeState(string $base64State): string
    {
        $decoded = preg_match('#^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$#D', $base64State) === 1
            ? base64_decode($base64State, true) : false;
        if ($decoded === false || ! self::canonicalBase64($base64State, $decoded)) {
            throw ApiError::message('Failed to decode '.EscapeDebug::of($base64State).' using base64');
        }
        if (! mb_check_encoding($decoded, 'UTF-8')) {
            throw ApiError::message('Invalid utf8 chars in '.EscapeDebug::of($base64State).' after base64 decoding');
        }

        return $decoded;
    }

    /**
     * authorize_url: the redirect URI the client's kind of app expects, and
     * where the user logs in. The login in progress is saved.
     *
     * @throws ApiError
     */
    public function authorizeUrl(string $state, string $clientChallenge, string $clientId, string $rawRedirectUri, ?string $bindingHash): string
    {
        // The desktop app uses the localhost callback when it cannot register its scheme.
        $localhost = in_array($rawRedirectUri, array_map(static fn (int $port): string => "http://localhost:{$port}", range(8065, 8070)), true)
            ? $rawRedirectUri : null;

        $redirectUri = match ($clientId) {
            'web', 'browser' => $this->config->string('domain').'/sso-connector.html',
            'desktop' => $localhost ?? 'bitwarden://sso-callback',
            'mobile' => 'bitwarden://sso-callback',
            'cli' => $localhost ?? throw ApiError::message('Unsupported redirect uri '.EscapeDebug::of($rawRedirectUri)),
            default => throw ApiError::message('Unsupported client '.EscapeDebug::of($clientId)),
        };

        [$url, $auth] = OidcClient::authorizeUrl($this->config, $state, $clientChallenge, $redirectUri, $bindingHash);
        $auth->save();

        return $url;
    }

    /**
     * exchange_code: who logged in, for the code the client got. A second
     * use, after the two-factor prompt, takes the stored answer once the
     * verifier is checked again.
     *
     * @return array{SsoAuth, AuthenticatedUser}
     *
     * @throws ApiError
     */
    public function exchangeCode(string $code, string $clientVerifier): array
    {
        $auth = SsoAuth::findByCode($code) ?? throw ApiError::message('Invalid code cannot retrieve sso auth');

        $authenticated = $auth->authenticatedUser();
        if ($authenticated !== null) {
            OidcClient::checkClientVerifier($clientVerifier, $auth);

            return [$auth, $authenticated];
        }

        $error = $auth->codeResponseError();
        if ($error !== null) {
            $auth->deleteAuth();
            throw ApiError::message('SSO authorization failed: '.EscapeDebug::of($error[0]).', '.EscapeDebug::of($error[1] ?? ''));
        }
        if ($auth->code_response === null) {
            $auth->deleteAuth();
            throw ApiError::message('Missing authorization provider return');
        }

        $client = OidcClient::cached($this->config);
        [$tokens, $idClaims] = $client->exchangeCode($auth->code_response, $clientVerifier, $auth);
        $accessToken = OidcClient::stringField($tokens, 'access_token') ?? '';
        $userInfo = $client->userInfo($accessToken);

        $email = self::claim($idClaims, 'email') ?? self::claim($userInfo, 'email') ?? throw ApiError::message('Neither id token nor userinfo contained an email');
        $emailVerified = self::boolClaim($idClaims, 'email_verified') ?? self::boolClaim($userInfo, 'email_verified');
        $userName = self::claim($idClaims, 'preferred_username') ?? self::claim($userInfo, 'preferred_username');

        $refreshToken = self::claim($tokens, 'refresh_token');
        if ($refreshToken === null && in_array('offline_access', preg_split('/\s+/', $this->config->string('sso_scopes'), flags: PREG_SPLIT_NO_EMPTY) ?: [], true)) {
            logger()->error('Scope offline_access is present but response contain no refresh_token');
        }

        $authenticated = new AuthenticatedUser(
            $refreshToken,
            $accessToken,
            OidcClient::expiresIn($tokens),
            OidcClient::stringField($idClaims, 'iss').'/'.OidcClient::stringField($idClaims, 'sub'),
            mb_strtolower($email),
            $emailVerified,
            $userName,
        );

        logger()->debug('Authenticated user '.($this->config->bool('sso_debug_tokens') ? $authenticated->debug() : $authenticated->identifier));
        $auth->auth_response = $authenticated->toJson();
        $auth->updated_at = Dates::now();
        $auth->save();

        return [$auth, $authenticated];
    }

    /**
     * redeem: after the two-factor login the login in progress is gone, the
     * user linked to the identity and the tokens made.
     *
     * @throws ApiError
     */
    public function redeem(Device $device, User $user, ?string $clientId, ?SsoUser $ssoUser, SsoAuth $auth, AuthenticatedUser $authenticated): AuthTokens
    {
        $auth->deleteAuth();

        if ($ssoUser === null) {
            SsoUser::new($user->uuid, $authenticated->identifier)->save();
        }

        return $this->createAuthTokens($device, $user, $clientId, $authenticated->refreshToken, $authenticated->accessToken, $authenticated->expiresIn);
    }

    /**
     * create_auth_tokens: a refresh token always, with the provider's refresh
     * token, or its access token to check the session at the user info.
     *
     * @throws ApiError
     */
    public function createAuthTokens(Device $device, User $user, ?string $clientId, ?string $refreshToken, string $accessToken, ?int $expiresIn): AuthTokens
    {
        if ($this->config->bool('sso_auth_only_not_session')) {
            return AuthTokens::new($device, $user, AuthMethod::Sso, $clientId, $this->jwt);
        }

        $now = Dates::now()->getTimestamp();
        $claims = $this->decodeTokenClaims('access_token', $accessToken);
        [$nbf, $exp] = match (true) {
            $claims !== null => $claims,
            $expiresIn !== null => [$now, $now + $expiresIn],
            default => throw ApiError::message('Non jwt access_token and empty expires_in'),
        };

        $accessClaims = LoginClaims::new($device, $user, $nbf, $exp, AuthMethod::Sso->scopes(), $clientId, $this->jwt);

        return $this->authTokens($device, $refreshToken, $accessClaims, $accessToken);
    }

    /**
     * exchange_refresh_token: a refresh with the provider's refresh token, or
     * with its access token while it is valid long enough and the user info
     * still answers.
     *
     * @param  array<string, mixed>  $refreshClaims
     *
     * @throws ApiError
     */
    public function exchangeRefreshToken(Device $device, User $user, ?string $clientId, array $refreshClaims): AuthTokens
    {
        $exp = is_int($refreshClaims['exp'] ?? null) ? $refreshClaims['exp'] : 0;
        $token = $refreshClaims['token'] ?? null;

        if (is_array($token) && is_string($token['Refresh'] ?? null)) {
            [$newRefreshToken, $accessToken, $expiresIn] = OidcClient::exchangeRefreshToken($this->config, $token['Refresh']);

            return $this->createAuthTokens($device, $user, $clientId, $newRefreshToken ?? $token['Refresh'], $accessToken, $expiresIn);
        }
        if (is_array($token) && is_string($token['Access'] ?? null)) {
            $now = Dates::now()->getTimestamp();
            if ($exp < $now + self::BW_EXPIRATION) {
                throw ApiError::silent('Access token is close to expiration but we have no refresh token');
            }
            OidcClient::checkValidity($this->config, $token['Access']);

            $accessClaims = LoginClaims::new($device, $user, $now, $exp, AuthMethod::Sso->scopes(), $clientId, $this->jwt);

            return $this->authTokens($device, null, $accessClaims, $token['Access']);
        }

        throw ApiError::message('No token present while in SSO');
    }

    /**
     * create_auth_tokens_impl
     */
    private function authTokens(Device $device, ?string $refreshToken, LoginClaims $accessClaims, string $accessToken): AuthTokens
    {
        if ($refreshToken !== null) {
            $now = Dates::now()->getTimestamp();
            [$nbf, $exp] = $this->decodeTokenClaims('refresh_token', $refreshToken) ?? [$now, $now + self::DEFAULT_REFRESH_VALIDITY];
            $token = ['Refresh' => $refreshToken];
        } else {
            [$nbf, $exp] = [$accessClaims->nbf, $accessClaims->exp];
            $token = ['Access' => $accessToken];
        }

        return AuthTokens::withClaims([
            'nbf' => $nbf,
            'exp' => $exp,
            'iss' => $this->jwt->issuer(JwtIssuer::Login),
            'sub' => AuthMethod::Sso->value,
            'device_token' => $device->refresh_token,
            'token' => $token,
        ], $accessClaims, AuthMethod::Sso, $this->jwt);
    }

    /**
     * decode_token_claims: nbf (or iat) and exp of a provider token that is a
     * JWT of SSO_AUTHORITY, read without checking its signature. Null where
     * it is none, expired more than a minute ago or from another issuer.
     *
     * @return array{int, int}|null
     */
    private function decodeTokenClaims(string $name, string $token): ?array
    {
        $claims = Jws::parse($token)?->payload;
        $exp = $claims->exp ?? null;
        if (! $claims instanceof stdClass || ! is_int($exp) || $exp < 0 || ! is_string($claims->iss ?? null)) {
            logger()->debug("Failed to decode basic token claims from {$name}");

            return null;
        }
        if ($exp < time() - 60) {
            logger()->debug("Expired Signature for base token claim from {$name}");

            return null;
        }
        if ($claims->iss !== $this->config->string('sso_authority')) {
            logger()->debug("Invalid Issuer for base token claim from {$name}");

            return null;
        }
        $nbf = $claims->nbf ?? $claims->iat ?? null;

        return [is_int($nbf) ? $nbf : Dates::now()->getTimestamp(), $exp];
    }

    private static function claim(stdClass $claims, string $name): ?string
    {
        $value = $claims->{$name} ?? null;

        return is_string($value) ? $value : null;
    }

    private static function boolClaim(stdClass $claims, string $name): ?bool
    {
        $value = $claims->{$name} ?? null;

        return is_bool($value) ? $value : null;
    }

    /**
     * data_encoding's BASE64 refuses padding bits that are not zero.
     */
    private static function canonicalBase64(string $encoded, string $decoded): bool
    {
        return base64_encode($decoded) === $encoded;
    }
}
