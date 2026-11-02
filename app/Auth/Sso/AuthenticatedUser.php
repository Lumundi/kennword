<?php

namespace App\Auth\Sso;

use App\Http\Json;
use App\Support\EscapeDebug;
use stdClass;

/**
 * OIDCAuthenticatedUser (src/db/models/sso_auth.rs): what the provider said
 * about the user, kept in sso_auth.auth_response between the code exchange
 * and the end of the two-factor login, as serde writes it.
 */
final readonly class AuthenticatedUser
{
    public function __construct(
        public ?string $refreshToken,
        public string $accessToken,
        public ?int $expiresIn,
        public string $identifier,
        public string $email,
        public ?bool $emailVerified,
        public ?string $userName,
    ) {}

    /**
     * The JSON of the derived Serialize: fields in order, the Duration as secs and nanos.
     */
    public function toJson(): string
    {
        return Json::encode([
            'refresh_token' => $this->refreshToken,
            'access_token' => $this->accessToken,
            'expires_in' => $this->expiresIn === null ? null : ['secs' => $this->expiresIn, 'nanos' => 0],
            'identifier' => $this->identifier,
            'email' => $this->email,
            'email_verified' => $this->emailVerified,
            'user_name' => $this->userName,
        ]);
    }

    /**
     * The derived Debug formatting, which SSO_DEBUG_TOKENS logs.
     */
    public function debug(): string
    {
        $option = static fn (?string $value): string => $value === null ? 'None' : 'Some('.EscapeDebug::debug($value).')';

        return 'OIDCAuthenticatedUser { refresh_token: '.$option($this->refreshToken)
            .', access_token: '.EscapeDebug::debug($this->accessToken)
            .', expires_in: '.($this->expiresIn === null ? 'None' : "Some({$this->expiresIn}s)")
            .', identifier: OIDCIdentifier('.EscapeDebug::debug($this->identifier).')'
            .', email: '.EscapeDebug::debug($this->email)
            .', email_verified: '.($this->emailVerified === null ? 'None' : 'Some('.($this->emailVerified ? 'true' : 'false').')')
            .', user_name: '.$option($this->userName).' }';
    }

    /**
     * Null where the stored JSON does not deserialize.
     */
    public static function fromJson(string $json): ?self
    {
        $data = json_decode($json);
        if (! $data instanceof stdClass) {
            return null;
        }
        $refreshToken = $data->refresh_token ?? null;
        $expiresIn = $data->expires_in ?? null;
        $seconds = $expiresIn instanceof stdClass ? ($expiresIn->secs ?? null) : null;
        $emailVerified = $data->email_verified ?? null;
        $userName = $data->user_name ?? null;
        if (! is_string($data->access_token ?? null) || ! is_string($data->identifier ?? null) || ! is_string($data->email ?? null)
            || ($refreshToken !== null && ! is_string($refreshToken)) || ($userName !== null && ! is_string($userName))
            || ($emailVerified !== null && ! is_bool($emailVerified)) || ($expiresIn !== null && ! is_int($seconds))) {
            return null;
        }

        return new self(
            is_string($refreshToken) ? $refreshToken : null,
            $data->access_token,
            is_int($seconds) ? $seconds : null,
            $data->identifier,
            $data->email,
            is_bool($emailVerified) ? $emailVerified : null,
            is_string($userName) ? $userName : null,
        );
    }
}
