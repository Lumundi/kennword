<?php

namespace App\Auth\Webauthn;

use App\Support\CborBytes;
use App\Support\CborMap;
use OpenSSLAsymmetricKey;
use stdClass;

/**
 * webauthn-rs's COSEKey: the algorithm and an EC2, OKP or RSA public key,
 * read from the authenticator's CBOR and stored as JSON, e.g.
 * {"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":"..","y":".."}}}.
 */
final readonly class CoseKey
{
    /**
     * COSEAlgorithm names and their COSE ids.
     */
    public const array ALGORITHMS = ['ES256' => -7, 'ES384' => -35, 'ES512' => -36, 'RS256' => -257, 'RS384' => -258, 'RS512' => -259,
        'PS256' => -37, 'PS384' => -38, 'PS512' => -39, 'EDDSA' => -8, 'INSECURE_RS1' => -65535];

    /**
     * ECDSA curves: COSE id, coordinate size and OID.
     */
    private const array EC_CURVES = ['SECP256R1' => [1, 32, '1.2.840.10045.3.1.7'], 'SECP384R1' => [2, 48, '1.3.132.0.34'], 'SECP521R1' => [3, 66, '1.3.132.0.35']];

    /**
     * EdDSA curves: COSE id, key size and OID.
     */
    private const array OKP_CURVES = ['ED25519' => [6, 32, '1.3.101.112'], 'ED448' => [7, 57, '1.3.101.113']];

    /**
     * @param  string  $type  The COSEAlgorithm name
     * @param  'EC_EC2'|'EC_OKP'|'RSA'  $kind
     */
    private function __construct(
        public string $type,
        public string $kind,
        public string $curve = '',
        public string $x = '',
        public string $y = '',
        public string $n = '',
        public string $e = '',
    ) {}

    /**
     * An ES256 key on P-256, as U2F registrations have.
     */
    public static function es256(string $x, string $y): self
    {
        return new self('ES256', 'EC_EC2', 'SECP256R1', $x, $y);
    }

    /**
     * TryFrom<&serde_cbor_2::Value> for COSEKey
     *
     * @throws WebauthnError
     */
    public static function fromCbor(mixed $value): self
    {
        if (! $value instanceof CborMap) {
            throw new WebauthnError('COSEKeyInvalidCBORValue');
        }
        $int = static fn (int $label): int => is_int($value->get($label)) ? $value->get($label) : throw new WebauthnError('COSEKeyInvalidCBORValue');
        $bytes = static fn (int $label): string => ($found = $value->get($label)) instanceof CborBytes ? $found->bytes : throw new WebauthnError('COSEKeyInvalidCBORValue');

        $kty = $int(1);
        $type = array_search($int(3), self::ALGORITHMS, true);
        if (! is_string($type)) {
            throw new WebauthnError('COSEKeyInvalidAlgorithm');
        }

        if ($kty === 2 && in_array($type, ['ES256', 'ES384', 'ES512'], true)) {
            $curve = self::curveName(self::EC_CURVES, $int(-1)) ?? throw new WebauthnError('COSEKeyECDSAInvalidCurve');
            [$x, $y] = [$bytes(-2), $bytes(-3)];
            if (strlen($x) !== self::EC_CURVES[$curve][1] || strlen($y) !== self::EC_CURVES[$curve][1]) {
                throw new WebauthnError('COSEKeyECDSAXYInvalid');
            }
            $key = new self($type, 'EC_EC2', $curve, $x, $y);
        } elseif ($kty === 3 && $type === 'RS256') {
            [$n, $e] = [$bytes(-1), $bytes(-2)];
            if (strlen($n) !== 256 || strlen($e) !== 3) {
                throw new WebauthnError('COSEKeyRSANEInvalid');
            }
            $key = new self($type, 'RSA', n: $n, e: $e);
        } elseif ($kty === 1 && $type === 'EDDSA') {
            $curve = self::curveName(self::OKP_CURVES, $int(-1)) ?? throw new WebauthnError('COSEKeyEDDSAInvalidCurve');
            $x = $bytes(-2);
            if (strlen($x) !== self::OKP_CURVES[$curve][1]) {
                throw new WebauthnError('COSEKeyEDDSAXInvalid');
            }
            $key = new self($type, 'EC_OKP', $curve, $x);
        } else {
            throw new WebauthnError('COSEKeyInvalidType');
        }

        $key->publicKey();

        return $key;
    }

    /**
     * The key as serde reads it from JSON; null when it does not fit.
     */
    public static function fromJson(mixed $value): ?self
    {
        if (! $value instanceof stdClass || ! is_string($value->type_ ?? null) || ! $value->key instanceof stdClass) {
            return null;
        }
        $type = self::algorithmName($value->type_);
        $variants = get_object_vars($value->key);
        if ($type === null || count($variants) !== 1) {
            return null;
        }
        $kind = (string) array_key_first($variants);
        $key = $variants[$kind];
        if (! $key instanceof stdClass) {
            return null;
        }

        return match ($kind) {
            'EC_EC2' => is_string($key->curve ?? null) && isset(self::EC_CURVES[$key->curve])
                && ($x = Base64UrlSafe::decode($key->x ?? null)) !== null && ($y = Base64UrlSafe::decode($key->y ?? null)) !== null
                ? new self($type, 'EC_EC2', $key->curve, $x, $y) : null,
            'EC_OKP' => is_string($key->curve ?? null) && isset(self::OKP_CURVES[$key->curve]) && ($x = Base64UrlSafe::decode($key->x ?? null)) !== null
                ? new self($type, 'EC_OKP', $key->curve, $x) : null,
            'RSA' => ($n = Base64UrlSafe::decode($key->n ?? null)) !== null && is_array($key->e ?? null) && count($key->e) === 3
                && ($e = Base64UrlSafe::decode($key->e)) !== null
                ? new self($type, 'RSA', n: $n, e: $e) : null,
            default => null,
        };
    }

    /**
     * @return array<string, mixed>
     */
    public function toJson(): array
    {
        $key = match ($this->kind) {
            'EC_EC2' => ['curve' => $this->curve, 'x' => Base64UrlSafe::encode($this->x), 'y' => Base64UrlSafe::encode($this->y)],
            'EC_OKP' => ['curve' => $this->curve, 'x' => Base64UrlSafe::encode($this->x)],
            'RSA' => ['n' => Base64UrlSafe::encode($this->n), 'e' => array_map(ord(...), str_split($this->e))],
        };

        return ['type_' => $this->type, 'key' => [$this->kind => $key]];
    }

    /**
     * COSEKey::verify_signature
     *
     * @throws WebauthnError
     */
    public function verify(string $signature, string $data): bool
    {
        return self::verifyWith($this->type, $this->publicKey(), $signature, $data, $this->kind === 'EC_OKP' ? $this->x : null);
    }

    /**
     * pkey_verify_signature: ES256 and RS256 with SHA-256, EdDSA; nothing else.
     *
     * @param  string|null  $ed25519  The raw key, for EdDSA
     *
     * @throws WebauthnError
     */
    public static function verifyWith(string $type, OpenSSLAsymmetricKey $key, string $signature, string $data, ?string $ed25519 = null): bool
    {
        return match ($type) {
            'ES256', 'RS256' => openssl_verify($data, $signature, $key, OPENSSL_ALGO_SHA256) === 1,
            'EDDSA' => strlen((string) $ed25519) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES && strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
                ? sodium_crypto_sign_verify_detached($signature, $data, (string) $ed25519)
                : throw new WebauthnError('OpenSSLError'),
            'INSECURE_RS1' => throw new WebauthnError('CredentialInsecureCryptography'),
            default => throw new WebauthnError('COSEKeyInvalidType'),
        };
    }

    /**
     * get_alg_key_ecc_x962_raw: 0x04 || x || y, for FIDO U2F.
     *
     * @throws WebauthnError
     */
    public function x962(): string
    {
        return $this->kind === 'EC_EC2' ? "\x04{$this->x}{$this->y}" : throw new WebauthnError('COSEKeyInvalidType');
    }

    /**
     * The key for OpenSSL, which also checks it (an EC point must lie on its curve).
     *
     * @throws WebauthnError
     */
    public function publicKey(): OpenSSLAsymmetricKey
    {
        $spki = match ($this->kind) {
            'EC_EC2' => Der::sequence(Der::sequence(Der::oid('1.2.840.10045.2.1'), Der::oid(self::EC_CURVES[$this->curve][2])), Der::bitString($this->x962())),
            'RSA' => Der::sequence(Der::sequence(Der::oid('1.2.840.113549.1.1.1'), Der::null()), Der::bitString(Der::sequence(Der::integer($this->n), Der::integer($this->e)))),
            'EC_OKP' => Der::sequence(Der::sequence(Der::oid(self::OKP_CURVES[$this->curve][2])), Der::bitString($this->x)),
        };

        return @openssl_pkey_get_public(Der::pem($spki, 'PUBLIC KEY')) ?: throw new WebauthnError('OpenSSLError');
    }

    /**
     * COSEAlgorithm's serde names, with the old ECDSA aliases.
     */
    public static function algorithmName(string $name): ?string
    {
        $name = ['ECDSA_SHA256' => 'ES256', 'ECDSA_SHA384' => 'ES384', 'ECDSA_SHA512' => 'ES512'][$name] ?? $name;

        return isset(self::ALGORITHMS[$name]) || $name === 'PinUvProtocol' ? $name : null;
    }

    /**
     * @param  array<string, array{int, int, string}>  $curves
     */
    private static function curveName(array $curves, int $id): ?string
    {
        foreach ($curves as $name => [$curveId]) {
            if ($curveId === $id) {
                return $name;
            }
        }

        return null;
    }
}
