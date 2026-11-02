<?php

namespace App\Auth\Sso;

use stdClass;

/**
 * Signed JWTs of an OpenID provider, checked like openidconnect's JWT code
 * does: the key from the provider's JWK set (by key id and compatible
 * type), and RS*, PS*, ES256, ES384, EdDSA or, with the client secret, HS*
 * signatures. RSA keys are held to the limits of the rsa crate. ES512 is
 * known, but openidconnect cannot verify P-521 signatures, so none is valid.
 */
final class Jws
{
    /**
     * Key type and hash of each signing algorithm.
     */
    private const array ALGORITHMS = [
        'RS256' => ['RSA', 'sha256'], 'RS384' => ['RSA', 'sha384'], 'RS512' => ['RSA', 'sha512'],
        'PS256' => ['RSA', 'sha256'], 'PS384' => ['RSA', 'sha384'], 'PS512' => ['RSA', 'sha512'],
        'ES256' => ['EC', 'sha256'], 'ES384' => ['EC', 'sha384'], 'ES512' => ['EC', 'sha512'],
        'HS256' => ['oct', 'sha256'], 'HS384' => ['oct', 'sha384'], 'HS512' => ['oct', 'sha512'],
        'EdDSA' => ['OKP', null],
    ];

    /**
     * The curves openidconnect verifies: their object identifier and the length of a coordinate.
     */
    private const array CURVES = ['P-256' => ['06082a8648ce3d030107', 32], 'P-384' => ['06052b81040022', 48]];

    /**
     * RsaPublicKey::MAX_SIZE and MAX_PUB_EXPONENT of the rsa crate.
     */
    private const int RSA_MAX_BITS = 4096;

    private const int RSA_MAX_EXPONENT = (1 << 33) - 1;

    /**
     * @param  stdClass  $header  The JOSE header
     * @param  stdClass  $payload  The claims
     */
    private function __construct(
        public readonly stdClass $header,
        public readonly stdClass $payload,
        private readonly string $signingInput,
        private readonly string $signature,
    ) {}

    /**
     * Null where the token is no compact JWS with JSON objects.
     */
    public static function parse(string $token): ?self
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }
        $header = json_decode(self::base64UrlDecode($parts[0]) ?? '');
        $payload = json_decode(self::base64UrlDecode($parts[1]) ?? '');
        $signature = self::base64UrlDecode($parts[2]);
        if (! $header instanceof stdClass || ! $payload instanceof stdClass || $signature === null) {
            return null;
        }

        return new self($header, $payload, "{$parts[0]}.{$parts[1]}", $signature);
    }

    public function algorithm(): ?string
    {
        return is_string($this->header->alg ?? null) ? $this->header->alg : null;
    }

    public static function usesSharedSecret(string $algorithm): bool
    {
        return (self::ALGORITHMS[$algorithm][0] ?? null) === 'oct';
    }

    public static function isKnown(string $algorithm): bool
    {
        return isset(self::ALGORITHMS[$algorithm]);
    }

    /**
     * JsonWebKeySet::filter_keys: the keys with the token's key id, if it
     * names one, that may sign with the algorithm.
     *
     * @param  list<stdClass>  $keys
     * @return list<stdClass>
     */
    public static function filterKeys(array $keys, ?string $keyId, string $algorithm): array
    {
        $type = self::ALGORITHMS[$algorithm][0] ?? null;

        return array_values(array_filter($keys, static fn (stdClass $key): bool => ($keyId === null || ($key->kid ?? null) === $keyId)
            && (! isset($key->use) || $key->use === 'sig')
            && ($key->kty ?? null) === $type
            && (! isset($key->alg) || $key->alg === $algorithm)));
    }

    /**
     * Whether the signature is valid for the key: a JWK, or the client secret for HS*.
     */
    public function verify(string $algorithm, stdClass|string $key): bool
    {
        [$type, $hash] = self::ALGORITHMS[$algorithm] ?? [null, null];

        if ($type === 'oct') {
            return is_string($key) && is_string($hash) && hash_equals(hash_hmac($hash, $this->signingInput, $key, true), $this->signature);
        }
        if (! $key instanceof stdClass) {
            return false;
        }
        if ($type === 'OKP') {
            $x = is_string($key->x ?? null) ? self::base64UrlDecode($key->x) : null;

            return ($key->crv ?? null) === 'Ed25519' && $x !== null && strlen($x) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
                && strlen($this->signature) === SODIUM_CRYPTO_SIGN_BYTES && sodium_crypto_sign_verify_detached($this->signature, $this->signingInput, $x);
        }
        if (! is_string($hash)) {
            return false;
        }
        if ($type === 'RSA') {
            $rsaKey = self::rsaKey($key);
            // rsa::Pkcs1v15Sign and rsa::Pss want a signature as long as the modulus.
            if ($rsaKey === null || strlen($this->signature) !== strlen($rsaKey[0])) {
                return false;
            }
            $pem = self::rsaPem(...$rsaKey);

            return str_starts_with($algorithm, 'PS')
                ? self::verifyPss($this->signingInput, $this->signature, $pem, $rsaKey[0], $hash)
                : openssl_verify($this->signingInput, $this->signature, $pem, $hash) === 1;
        }

        $pem = self::ecPem($key, $algorithm);
        // p256::ecdsa::Signature::from_slice takes r and s of the curve's size only.
        if ($pem === null || strlen($this->signature) !== ($algorithm === 'ES256' ? 64 : 96)) {
            return false;
        }

        return openssl_verify($this->signingInput, self::ecDerSignature($this->signature), $pem, $hash) === 1;
    }

    public static function base64UrlDecode(string $value): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/D', $value) !== 1) {
            return null;
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    /**
     * Modulus and exponent of a JWK, without leading zeros, if
     * RsaPublicKey::new takes them: a modulus of at most 4096 bits, both odd,
     * and an exponent from 2 to 2^33 - 1, below the modulus.
     *
     * @return array{string, string}|null
     */
    private static function rsaKey(stdClass $key): ?array
    {
        $n = ltrim((string) (is_string($key->n ?? null) ? self::base64UrlDecode($key->n) : ''), "\0");
        $e = ltrim((string) (is_string($key->e ?? null) ? self::base64UrlDecode($key->e) : ''), "\0");
        if ($n === '' || $e === '' || strlen($e) > 5) {
            return null;
        }
        $exponent = (int) hexdec(bin2hex($e));
        $bits = 8 * strlen($n) - (8 - strlen(decbin(ord($n[0]))));
        $odd = static fn (string $number): bool => (ord($number[strlen($number) - 1]) & 1) === 1;
        $below = strlen($e) < strlen($n) || (strlen($e) === strlen($n) && strcmp($e, $n) < 0);
        if ($bits > self::RSA_MAX_BITS || ! $below || ! $odd($n) || ! $odd($e) || $exponent < 2 || $exponent > self::RSA_MAX_EXPONENT) {
            return null;
        }

        return [$n, $e];
    }

    private static function rsaPem(string $n, string $e): string
    {
        $rsaKey = self::der(0x30, self::derInteger($n).self::derInteger($e));
        $algorithm = self::der(0x30, hex2bin('06092a864886f70d0101010500') ?: '');

        return self::pem(self::der(0x30, $algorithm.self::der(0x03, "\0".$rsaKey)));
    }

    /**
     * RSASSA-PSS as the rsa crate verifies it (RFC 8017 section 9.1.2): MGF1
     * with the message's hash, and a salt exactly as long as the hash.
     */
    private static function verifyPss(string $message, string $signature, string $pem, string $modulus, string $hash): bool
    {
        if (! openssl_public_decrypt($signature, $decrypted, $pem, OPENSSL_NO_PADDING) || ! is_string($decrypted)) {
            return false;
        }
        $keyBits = 8 * strlen($modulus) - (8 - strlen(decbin(ord($modulus[0]))));
        $emBits = $keyBits - 1;
        $emLength = intdiv($emBits + 7, 8);
        $em = substr(str_pad($decrypted, strlen($modulus), "\0", STR_PAD_LEFT), strlen($modulus) - $emLength);
        $messageHash = hash($hash, $message, true);
        $hashLength = strlen($messageHash);
        $saltLength = $hashLength;
        if ($emLength < $hashLength + $saltLength + 2 || $em[$emLength - 1] !== "\xBC") {
            return false;
        }

        $maskedDb = substr($em, 0, $emLength - $hashLength - 1);
        $h = substr($em, $emLength - $hashLength - 1, $hashLength);
        $zeroBits = 8 * $emLength - $emBits;
        if ($zeroBits > 0 && (ord($maskedDb[0]) & (0xFF << (8 - $zeroBits)) & 0xFF) !== 0) {
            return false;
        }

        $mask = '';
        for ($counter = 0; strlen($mask) < strlen($maskedDb); $counter++) {
            $mask .= hash($hash, $h.pack('N', $counter), true);
        }
        $db = $maskedDb ^ substr($mask, 0, strlen($maskedDb));
        $db[0] = chr(ord($db[0]) & (0xFF >> $zeroBits));

        $padding = $emLength - $hashLength - $saltLength - 2;
        if (strspn($db, "\0", 0, $padding) !== $padding || $db[$padding] !== "\x01") {
            return false;
        }
        $salt = substr($db, -$saltLength);

        return hash_equals($h, hash($hash, str_repeat("\0", 8).$messageHash.$salt, true));
    }

    private static function ecPem(stdClass $key, string $algorithm): ?string
    {
        $curve = is_string($key->crv ?? null) ? $key->crv : '';
        $expected = ['ES256' => 'P-256', 'ES384' => 'P-384'][$algorithm] ?? null;
        $x = is_string($key->x ?? null) ? self::base64UrlDecode($key->x) : null;
        $y = is_string($key->y ?? null) ? self::base64UrlDecode($key->y) : null;
        // openidconnect puts x and y behind 0x04 as they are; VerifyingKey::from_sec1_bytes
        // only takes a point as long as both coordinates of the curve together.
        if ($expected === null || $curve !== $expected || $x === null || $y === null
            || strlen($x) + strlen($y) !== 2 * self::CURVES[$curve][1]) {
            return null;
        }
        $algorithmId = self::der(0x30, (hex2bin('06072a8648ce3d0201') ?: '').(hex2bin(self::CURVES[$curve][0]) ?: ''));

        return self::pem(self::der(0x30, $algorithmId.self::der(0x03, "\0\x04".$x.$y)));
    }

    /**
     * The raw r and s of a JWS ECDSA signature as the DER sequence OpenSSL expects.
     */
    private static function ecDerSignature(string $signature): string
    {
        $half = intdiv(strlen($signature), 2);

        return self::der(0x30, self::derInteger(substr($signature, 0, $half)).self::derInteger(substr($signature, $half)));
    }

    private static function derInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\0");
        if ($bytes === '' || (ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\0".$bytes;
        }

        return self::der(0x02, $bytes);
    }

    private static function der(int $tag, string $content): string
    {
        $length = strlen($content);
        if ($length < 0x80) {
            return chr($tag & 0xFF).chr($length & 0xFF).$content;
        }
        $lengthBytes = ltrim(pack('N', $length), "\0");

        return chr($tag & 0xFF).chr((0x80 | strlen($lengthBytes)) & 0xFF).$lengthBytes.$content;
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END PUBLIC KEY-----\n";
    }
}
