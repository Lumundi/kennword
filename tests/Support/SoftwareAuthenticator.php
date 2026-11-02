<?php

namespace Tests\Support;

use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * A WebAuthn authenticator in software, with an ES256 key: it answers the
 * options of a registration or a login like a browser and security key
 * would, with "none", packed (self or with a certificate) or FIDO U2F
 * attestation. Maps are written in the order given, as CTAP does.
 */
final class SoftwareAuthenticator
{
    public readonly string $credentialId;

    private OpenSSLAsymmetricKey $key;

    public int $counter = 0;

    public function __construct(
        private readonly string $origin = 'http://localhost',
        public bool $backupEligible = false,
        public bool $backupState = false,
        ?string $credentialId = null,
        ?OpenSSLAsymmetricKey $key = null,
    ) {
        $this->credentialId = $credentialId ?? random_bytes(32);
        $this->key = $key ?? self::ecKey();
    }

    /**
     * What another process needs to go on as this authenticator (see restore()).
     *
     * @return array{origin: string, credentialId: string, key: string, counter: int}
     */
    public function export(): array
    {
        if (! openssl_pkey_export($this->key, $pem) || ! is_string($pem)) {
            throw new RuntimeException('Cannot export the key');
        }

        return ['origin' => $this->origin, 'credentialId' => self::base64($this->credentialId), 'key' => $pem, 'counter' => $this->counter];
    }

    /**
     * @param  array<mixed>  $exported  What export() returned
     */
    public static function restore(array $exported): self
    {
        $key = openssl_pkey_get_private(self::string($exported['key'] ?? null)) ?: throw new RuntimeException('Cannot read the key');
        $credentialId = base64_decode(strtr(self::string($exported['credentialId'] ?? null), '-_', '+/'), true);
        $authenticator = new self(self::string($exported['origin'] ?? null), credentialId: is_string($credentialId) ? $credentialId : null, key: $key);
        $authenticator->counter = is_int($exported['counter'] ?? null) ? $exported['counter'] : 0;

        return $authenticator;
    }

    /**
     * The device response of a registration.
     *
     * @param  array<mixed>  $options  The publicKey options of the server
     * @param  'none'|'packed'|'packed-x5c'|'fido-u2f'  $format
     * @return array<string, mixed>
     */
    public function register(array $options, string $format = 'none', ?string $origin = null, ?string $type = null): array
    {
        $rp = is_array($options['rp'] ?? null) ? $options['rp'] : [];
        $rpIdHash = hash('sha256', is_string($rp['id'] ?? null) ? $rp['id'] : '', true);
        $clientData = $this->clientData($type ?? 'webauthn.create', self::string($options['challenge'] ?? null), $origin);
        $clientDataHash = hash('sha256', $clientData, true);

        $credential = str_repeat("\0", 16).pack('n', strlen($this->credentialId)).$this->credentialId.$this->coseKey();
        $authData = $rpIdHash.chr((0x41 | $this->backupFlags()) & 0xFF).pack('N', $this->counter).$credential;

        $statement = match ($format) {
            'none' => self::map([]),
            'packed' => self::map([['alg', -7], ['sig', self::bytes($this->sign($authData.$clientDataHash))]]),
            'packed-x5c', 'fido-u2f' => $this->certified($format, $authData, $rpIdHash, $clientDataHash),
        };
        $object = self::map([['fmt', $format === 'packed-x5c' ? 'packed' : $format], ['attStmt', $statement], ['authData', self::bytes($authData)]]);

        return [
            'id' => self::base64($this->credentialId),
            'rawId' => self::base64($this->credentialId),
            'type' => 'public-key',
            'response' => ['AttestationObject' => self::base64(self::cbor($object)), 'clientDataJson' => self::base64($clientData)],
        ];
    }

    /**
     * The 2FA token of a login: the assertion as JSON.
     *
     * @param  array<mixed>  $options  The publicKey options of the login prompt
     */
    public function assert(array $options, ?string $origin = null, bool $tamper = false, ?int $counter = null, ?string $appid = null): string
    {
        $this->counter = $counter ?? $this->counter + 1;
        // A key registered with U2F signs for the AppID.
        $rpIdHash = hash('sha256', $appid ?? self::string($options['rpId'] ?? null), true);
        $authData = $rpIdHash.chr((0x01 | $this->backupFlags()) & 0xFF).pack('N', $this->counter);
        $clientData = $this->clientData('webauthn.get', self::string($options['challenge'] ?? null), $origin);
        $signature = $this->sign($authData.hash('sha256', $clientData, true).($tamper ? 'x' : ''));

        return (string) json_encode([
            'id' => self::base64($this->credentialId),
            'rawId' => self::base64($this->credentialId),
            'type' => 'public-key',
            'response' => ['authenticatorData' => self::base64($authData), 'clientDataJson' => self::base64($clientData),
                'signature' => self::base64($signature), 'userHandle' => null],
            'extensions' => $appid === null ? new \stdClass : ['appid' => true],
        ]);
    }

    private function clientData(string $type, string $challenge, ?string $origin): string
    {
        return (string) json_encode(['type' => $type, 'challenge' => $challenge, 'origin' => $origin ?? $this->origin, 'crossOrigin' => false], JSON_UNESCAPED_SLASHES);
    }

    private function backupFlags(): int
    {
        return ($this->backupEligible ? 0x08 : 0) | ($this->backupState ? 0x10 : 0);
    }

    /**
     * An attestation statement with a certificate: packed with one meeting
     * the packed requirements, or FIDO U2F.
     */
    private function certified(string $format, string $authData, string $rpIdHash, string $clientDataHash): CborMapValue
    {
        $key = self::ecKey();
        $subject = $format === 'packed-x5c'
            ? ['countryName' => 'DE', 'organizationName' => 'Kennword', 'organizationalUnitName' => 'Authenticator Attestation', 'commonName' => 'Test key']
            : ['commonName' => 'U2F test key'];
        $config = (string) tempnam(sys_get_temp_dir(), 'openssl');
        file_put_contents($config, "[req]\ndistinguished_name=dn\n[dn]\n[ext]\nbasicConstraints=critical,CA:FALSE\n");
        $csrKey = $key;
        $csr = openssl_csr_new($subject, $csrKey, ['config' => $config, 'digest_alg' => 'sha256']);
        $certificate = $csr === false || $csr === true ? false : openssl_csr_sign($csr, null, $key, 1, ['config' => $config, 'x509_extensions' => 'ext', 'digest_alg' => 'sha256']);
        unlink($config);
        if ($certificate === false || ! openssl_x509_export($certificate, $pem) || ! is_string($pem)) {
            throw new RuntimeException('Cannot create the attestation certificate');
        }
        $der = (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', $pem));

        $signed = $format === 'fido-u2f'
            ? "\0".$rpIdHash.$clientDataHash.$this->credentialId."\x04".$this->coordinates()
            : $authData.$clientDataHash;
        $entries = [['sig', self::bytes(self::signWith($key, $signed))], ['x5c', [self::bytes($der)]]];

        return self::map($format === 'packed-x5c' ? [['alg', -7], ...$entries] : $entries);
    }

    private function sign(string $data): string
    {
        return self::signWith($this->key, $data);
    }

    private static function signWith(OpenSSLAsymmetricKey $key, string $data): string
    {
        return openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256) && is_string($signature) ? $signature : throw new RuntimeException('Cannot sign');
    }

    /**
     * The COSE key: kty EC2, alg ES256, crv P-256, x, y.
     */
    private function coseKey(): string
    {
        $coordinates = $this->coordinates();

        return self::cbor(self::map([[1, 2], [3, -7], [-1, 1], [-2, self::bytes(substr($coordinates, 0, 32))], [-3, self::bytes(substr($coordinates, 32))]]));
    }

    /**
     * The uncompressed public key: 0x04, x and y.
     */
    public function publicKey(): string
    {
        return "\x04".$this->coordinates();
    }

    private function coordinates(): string
    {
        $details = openssl_pkey_get_details($this->key) ?: [];
        $ec = is_array($details['ec'] ?? null) ? $details['ec'] : [];

        return str_pad(self::string($ec['x'] ?? null), 32, "\0", STR_PAD_LEFT).str_pad(self::string($ec['y'] ?? null), 32, "\0", STR_PAD_LEFT);
    }

    private static function ecKey(): OpenSSLAsymmetricKey
    {
        return openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']) ?: throw new RuntimeException('Cannot create a key');
    }

    public static function base64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function string(mixed $value): string
    {
        return is_string($value) ? $value : throw new RuntimeException('Expected a string');
    }

    /**
     * @param  list<array{int|string, mixed}>  $entries
     */
    private static function map(array $entries): CborMapValue
    {
        return new CborMapValue($entries);
    }

    private static function bytes(string $bytes): CborBytesValue
    {
        return new CborBytesValue($bytes);
    }

    /**
     * CBOR of integers, byte and text strings, arrays and ordered maps.
     */
    public static function cbor(mixed $value): string
    {
        $head = static function (int $major, int $length): string {
            return match (true) {
                $length < 24 => chr((($major << 5) | $length) & 0xFF),
                $length < 0x100 => chr((($major << 5) | 24) & 0xFF).chr($length & 0xFF),
                $length < 0x10000 => chr((($major << 5) | 25) & 0xFF).pack('n', $length),
                default => chr((($major << 5) | 26) & 0xFF).pack('N', $length),
            };
        };

        return match (true) {
            is_int($value) && $value >= 0 => $head(0, $value),
            is_int($value) => $head(1, -1 - $value),
            $value instanceof CborBytesValue => $head(2, strlen($value->bytes)).$value->bytes,
            is_string($value) => $head(3, strlen($value)).$value,
            is_array($value) => $head(4, count($value)).implode('', array_map(self::cbor(...), $value)),
            $value instanceof CborMapValue => $head(5, count($value->entries)).implode('', array_map(
                static fn (array $entry): string => self::cbor($entry[0]).self::cbor($entry[1]), $value->entries)),
            default => throw new RuntimeException('Cannot encode this value as CBOR'),
        };
    }
}
