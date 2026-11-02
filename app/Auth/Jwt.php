<?php

namespace App\Auth;

use App\Config\Config;
use App\Http\ApiError;
use App\Http\Json;
use RuntimeException;
use stdClass;

/**
 * Vaultwarden's tokens (auth::encode_jwt / decode_jwt): RS256, 30 seconds of
 * leeway, and the checks and messages of the jsonwebtoken crate.
 */
final readonly class Jwt
{
    public const int LEEWAY = 30;

    /**
     * Header::new(RS256) serializes these two fields in this order.
     */
    private const array HEADER = ['typ' => 'JWT', 'alg' => 'RS256'];

    public function __construct(
        private RsaKeys $keys,
        private Config $config,
    ) {}

    public function issuer(JwtIssuer $issuer): string
    {
        return $this->config->string('domain_origin').'|'.$issuer->value;
    }

    /**
     * @param  array<string, mixed>  $claims  In the field order of the Rust claims struct
     */
    public function encode(array $claims): string
    {
        $input = self::base64Url(Json::encode(self::HEADER)).'.'.self::base64Url(Json::encode($claims));

        if (! openssl_sign($input, $signature, $this->keys->privateKey(), OPENSSL_ALGO_SHA256) || ! is_string($signature)) {
            throw new RuntimeException('Error encoding jwt '.openssl_error_string());
        }

        return $input.'.'.self::base64Url($signature);
    }

    /**
     * The fields of InviteJwtClaims, which the invitation token must have.
     */
    public const array INVITE_CLAIMS = ['nbf' => 'int', 'exp' => 'int', 'iss' => 'string', 'sub' => 'string', 'email' => 'string',
        'org_id' => 'string', 'member_id' => 'string', 'invited_by_email' => '?string'];

    /**
     * The fields of RegisterVerifyClaims.
     */
    public const array REGISTER_VERIFY_CLAIMS = ['nbf' => 'int', 'exp' => 'int', 'iss' => 'string', 'sub' => 'string', 'name' => '?string', 'verified' => 'bool'];

    /**
     * The fields of EmergencyAccessInviteJwtClaims.
     */
    public const array EMERGENCY_ACCESS_INVITE_CLAIMS = ['nbf' => 'int', 'exp' => 'int', 'iss' => 'string', 'sub' => 'string', 'email' => 'string',
        'emer_id' => 'string', 'grantor_name' => 'string', 'grantor_email' => 'string'];

    /**
     * @param  array<string, 'int'|'string'|'?string'|'bool'>  $fields  The claims struct, in field order: jsonwebtoken
     *                                                                  deserializes it before it validates the token
     * @param  array{string, string, bool}|null  $nested  A field holding a struct that denies unknown fields:
     *                                                    its name, the one field of that struct and whether it is required
     * @return array<string, mixed> The claims
     *
     * @throws ApiError
     */
    public function decode(string $token, JwtIssuer $issuer, ?int $now = null, array $fields = [], ?array $nested = null): array
    {
        $token = (string) preg_replace('/\s+/u', '', $token);

        // jsonwebtoken splits off the signature and the payload from the right.
        $signatureStart = strrpos($token, '.');
        $payloadStart = $signatureStart === false ? false : strrpos(substr($token, 0, $signatureStart), '.');
        if ($signatureStart === false || $payloadStart === false) {
            throw ApiError::message('Token is invalid');
        }

        $header = self::decodePart(substr($token, 0, $payloadStart));
        if (($header['alg'] ?? null) !== 'RS256') {
            throw self::error(is_string($header['alg'] ?? null) ? 'InvalidAlgorithm' : 'Json');
        }

        $signature = self::base64UrlDecode(substr($token, $signatureStart + 1));
        if (openssl_verify(substr($token, 0, $signatureStart), $signature, $this->keys->publicKey(), OPENSSL_ALGO_SHA256) !== 1) {
            throw self::error('InvalidSignature');
        }

        $payload = substr($token, $payloadStart + 1, $signatureStart - $payloadStart - 1);
        $claims = self::decodePart($payload);
        $json = self::base64UrlDecode($payload);
        if ($nested !== null) {
            self::deserializeNested($claims, $nested, $json);
        }
        self::deserialize($claims, $fields, $json);
        $this->validate($claims, $this->issuer($issuer), $now ?? time());

        return $claims;
    }

    /**
     * serde's deserialization of the claims struct: the first missing field
     * is reported where the object ends. Wrong types are reported less exactly.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, 'int'|'string'|'?string'|'bool'>  $fields
     */
    private static function deserialize(array $claims, array $fields, string $json): void
    {
        foreach ($fields as $name => $type) {
            if (! array_key_exists($name, $claims)) {
                if ($type === '?string') {
                    continue;
                }
                $end = strrpos($json, '}');

                throw self::serdeError("missing field `{$name}`", $json, $end === false ? strlen($json) - 1 : $end);
            }
            $value = $claims[$name];
            $valid = match ($type) {
                'int' => is_int($value),
                'string' => is_string($value),
                '?string' => $value === null || is_string($value),
                'bool' => is_bool($value),
            };
            if (! $valid) {
                throw self::error('Json');
            }
        }
    }

    /**
     * The struct in one field of the claims, which denies unknown fields:
     * serde reports an unknown or repeated field right after its name and a
     * missing one where the inner object ends.
     *
     * @param  array<string, mixed>  $claims
     * @param  array{string, string, bool}  $nested
     */
    private static function deserializeNested(array $claims, array $nested, string $json): void
    {
        [$outer, $field, $required] = $nested;
        if (! array_key_exists($outer, $claims)) {
            return;
        }
        $start = preg_match('/"'.preg_quote($outer, '/').'"\s*:\s*\{/', $json, $match, PREG_OFFSET_CAPTURE) === 1
            ? $match[0][1] + strlen($match[0][0]) - 1
            : null;
        if (! is_array($claims[$outer]) || $start === null) {
            throw self::error('Json');
        }

        $seen = false;
        $depth = 0;
        $inString = false;
        $keyStart = null;
        $expectKey = true;
        for ($i = $start + 1, $length = strlen($json); $i < $length; $i++) {
            $char = $json[$i];
            if ($inString) {
                if ($char === '\\') {
                    $i++;
                } elseif ($char === '"') {
                    $inString = false;
                    if ($keyStart !== null) {
                        $key = json_decode(substr($json, $keyStart, $i - $keyStart + 1));
                        $keyStart = null;
                        if ($key !== $field) {
                            throw self::serdeError('unknown field `'.(is_string($key) ? $key : '')."`, expected `{$field}`", $json, $i);
                        }
                        if ($seen) {
                            throw self::serdeError("duplicate field `{$field}`", $json, $i);
                        }
                        $seen = true;
                    }
                }

                continue;
            }
            if ($char === '"') {
                $inString = true;
                if ($depth === 0 && $expectKey) {
                    $keyStart = $i;
                    $expectKey = false;
                }
            } elseif ($char === '{' || $char === '[') {
                $depth++;
            } elseif ($char === ']' || ($char === '}' && $depth > 0)) {
                $depth--;
            } elseif ($char === ',' && $depth === 0) {
                $expectKey = true;
            } elseif ($char === '}') {
                if ($required && ! $seen) {
                    throw self::serdeError("missing field `{$field}`", $json, $i);
                }

                return;
            }
        }
    }

    /**
     * A serde_json error at the character with the index, in Debug format.
     */
    private static function serdeError(string $message, string $json, int $index): ApiError
    {
        $before = substr($json, 0, $index + 1);
        $newline = strrpos($before, "\n");
        $line = substr_count($before, "\n") + 1;
        $column = $newline === false ? strlen($before) : strlen($before) - $newline - 1;

        return self::error('Json(Error('.json_encode($message, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE).", line: {$line}, column: {$column}))");
    }

    /**
     * jsonwebtoken's validation: required exp, then exp, nbf, iss and aud.
     *
     * @param  array<string, mixed>  $claims
     */
    private function validate(array $claims, string $issuer, int $now): void
    {
        $exp = $claims['exp'] ?? null;
        $nbf = $claims['nbf'] ?? null;

        if (! is_int($exp) || $exp < 0) {
            throw self::error('MissingRequiredClaim("exp")');
        }
        if ($exp < $now - self::LEEWAY) {
            throw ApiError::message('Token has expired');
        }
        if (is_int($nbf) && $nbf >= 0 && $nbf > $now + self::LEEWAY) {
            throw self::error('ImmatureSignature');
        }

        $iss = $claims['iss'] ?? null;
        if ((is_string($iss) && $iss !== $issuer) || (is_array($iss) && $iss !== [$issuer] && ! in_array($issuer, $iss, true))) {
            throw ApiError::message('Issuer is invalid');
        }

        if (array_key_exists('aud', $claims)) {
            throw self::error('InvalidAudience');
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodePart(string $part): array
    {
        $decoded = json_decode(self::base64UrlDecode($part));
        if (! $decoded instanceof stdClass) {
            throw self::error('Json');
        }

        $values = [];
        foreach (get_object_vars($decoded) as $name => $value) {
            $values[(string) $name] = self::toArray($value);
        }

        return $values;
    }

    private static function toArray(mixed $value): mixed
    {
        if ($value instanceof stdClass) {
            $value = get_object_vars($value);
        }

        return is_array($value) ? array_map(self::toArray(...), $value) : $value;
    }

    private static function base64Url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * URL-safe base64 without padding, as jsonwebtoken requires it. Like the base64 crate, the unused bits
     * of the last character must be zero, so that every value has one spelling.
     */
    private static function base64UrlDecode(string $data): string
    {
        if (! preg_match('/^[A-Za-z0-9_-]*$/D', $data) || strlen($data) % 4 === 1) {
            throw self::error('Base64');
        }

        $decoded = (string) base64_decode(strtr($data, '-_', '+/'), true);
        if (self::base64Url($decoded) !== $data) {
            throw self::error('Base64');
        }

        return $decoded;
    }

    /**
     * Errors without a message of their own show jsonwebtoken's error kind.
     */
    private static function error(string $kind): ApiError
    {
        return ApiError::message("Error decoding JWT: Error({$kind})");
    }
}
