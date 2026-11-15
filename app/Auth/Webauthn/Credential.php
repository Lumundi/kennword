<?php

namespace App\Auth\Webauthn;

use stdClass;

/**
 * webauthn-rs-core's CredentialV5, as Vaultwarden stores it inside a
 * Passkey ({"cred": ...}). JSON is read with serde's rules (unknown fields
 * ignored, aliases accepted) and written in field order, so that a record
 * written by Vaultwarden comes back the same.
 */
final class Credential
{
    public const array TRANSPORTS = ['usb', 'nfc', 'ble', 'internal', 'hybrid', 'test'];

    public const array FORMATS = ['packed' => 'packed', 'Packed' => 'packed', 'tpm' => 'tpm', 'Tpm' => 'tpm', 'TPM' => 'tpm',
        'android-key' => 'android-key', 'AndroidKey' => 'android-key', 'android-safetynet' => 'android-safetynet',
        'AndroidSafetyNet' => 'android-safetynet', 'AndroidSafetynet' => 'android-safetynet', 'fido-u2f' => 'fido-u2f',
        'FIDOU2F' => 'fido-u2f', 'apple' => 'apple', 'AppleAnonymous' => 'apple', 'none' => 'none', 'None' => 'none'];

    private const array PROTECTION = ['userVerificationOptional', 'userVerificationOptionalWithCredentialIDList', 'userVerificationRequired'];

    /**
     * @param  list<string>|null  $transports
     * @param  array{cred_protect: mixed, hmac_create_secret: mixed, appid: mixed, cred_props: mixed}  $extensions  ExtnState JSON values
     * @param  string|array{0: string, 1: list<string>}  $attestationData  A unit variant, or a variant with its DER certificates
     * @param  mixed  $attestationMetadata  AttestationMetadata JSON value
     */
    public function __construct(
        public string $credId,
        public CoseKey $cred,
        public int $counter,
        public ?array $transports,
        public bool $userVerified,
        public bool $backupEligible,
        public bool $backupState,
        public string $registrationPolicy,
        public array $extensions,
        public string|array $attestationData,
        public mixed $attestationMetadata,
        public string $attestationFormat,
    ) {}

    /**
     * A credential of before webauthn-rs knew backup flags, extensions and
     * attestation (CredentialV3, and the U2F migration).
     */
    public static function legacy(string $credId, CoseKey $key, int $counter, bool $userVerified, string $policy): self
    {
        return new self($credId, $key, $counter, null, $userVerified, false, false, $policy,
            ['cred_protect' => 'NotRequested', 'hmac_create_secret' => 'NotRequested', 'appid' => 'NotRequested', 'cred_props' => 'NotRequested'],
            'None', 'None', 'none');
    }

    /**
     * Null when serde would not read the value.
     */
    public static function fromJson(mixed $value): ?self
    {
        if (! $value instanceof stdClass) {
            return null;
        }
        $credId = Base64UrlSafe::decode($value->cred_id ?? null);
        $cred = CoseKey::fromJson($value->cred ?? null);
        $counter = $value->counter ?? null;
        $transports = self::transports($value->transports ?? null);
        $policy = $value->registration_policy ?? null;
        $extensions = self::extensions($value->extensions ?? null);
        $attestation = $value->attestation ?? null;
        $data = $attestation instanceof stdClass ? self::attestationData($attestation->data ?? null) : null;
        $metadata = $attestation instanceof stdClass ? self::metadata($attestation->metadata ?? null) : null;
        $format = self::FORMATS[is_string($value->attestation_format ?? null) ? $value->attestation_format : ''] ?? null;

        if ($credId === null || $cred === null || ! is_int($counter) || $counter < 0 || $counter > 0xFFFFFFFF || $transports === false
            || ! is_bool($value->user_verified ?? null) || ! is_bool($value->backup_eligible ?? null) || ! is_bool($value->backup_state ?? null)
            || ! in_array($policy, ['required', 'preferred', 'discouraged'], true) || $extensions === null || $data === null || $metadata === null || $format === null) {
            return null;
        }

        return new self($credId, $cred, $counter, $transports, $value->user_verified, $value->backup_eligible, $value->backup_state,
            $policy, $extensions, $data, $metadata[0], $format);
    }

    /**
     * @return array<string, mixed>
     */
    public function toJson(): array
    {
        $data = is_string($this->attestationData) ? $this->attestationData
            : [$this->attestationData[0] => array_map(Base64UrlSafe::encode(...), $this->attestationData[1])];

        return [
            'cred_id' => Base64UrlSafe::encode($this->credId),
            'cred' => $this->cred->toJson(),
            'counter' => $this->counter,
            'transports' => $this->transports,
            'user_verified' => $this->userVerified,
            'backup_eligible' => $this->backupEligible,
            'backup_state' => $this->backupState,
            'registration_policy' => $this->registrationPolicy,
            'extensions' => $this->extensions,
            'attestation' => ['data' => $data, 'metadata' => $this->attestationMetadata],
            'attestation_format' => $this->attestationFormat,
        ];
    }

    /**
     * Option<Vec<AuthenticatorTransport>>: unknown names become "unknown".
     *
     * @return list<string>|null|false False when it does not parse
     */
    private static function transports(mixed $value): array|null|false
    {
        if ($value === null) {
            return null;
        }
        if (! is_array($value) || ! array_is_list($value)) {
            return false;
        }
        $transports = [];
        foreach ($value as $transport) {
            if (! is_string($transport)) {
                return false;
            }
            $transports[] = in_array($transport, self::TRANSPORTS, true) ? $transport : 'unknown';
        }

        return $transports;
    }

    /**
     * RegisteredExtensions: every field defaults to NotRequested.
     *
     * @return array{cred_protect: mixed, hmac_create_secret: mixed, appid: mixed, cred_props: mixed}|null
     */
    private static function extensions(mixed $value): ?array
    {
        if (! $value instanceof stdClass) {
            return null;
        }
        $protection = static fn (mixed $v): bool => in_array($v, self::PROTECTION, true);
        $bool = is_bool(...);
        $props = static fn (mixed $v): bool => $v instanceof stdClass && (! property_exists($v, 'rk') || $v->rk === null || is_bool($v->rk));

        $result = [];
        foreach (['cred_protect' => $protection, 'hmac_create_secret' => $bool, 'appid' => $bool, 'cred_props' => $props] as $name => $check) {
            $state = property_exists($value, $name) ? self::extensionState($value->{$name}, $check) : 'NotRequested';
            if ($state === null) {
                return null;
            }
            $result[$name] = $state;
        }

        return ['cred_protect' => $result['cred_protect'], 'hmac_create_secret' => $result['hmac_create_secret'],
            'appid' => $result['appid'], 'cred_props' => $result['cred_props']];
    }

    /**
     * ExtnState<T>: "NotRequested", "Ignored" or {"Set"|"Unsolicited"|"Unsigned": T}.
     *
     * @param  callable(mixed): bool  $check
     */
    private static function extensionState(mixed $value, callable $check): mixed
    {
        if ($value === 'NotRequested' || $value === 'Ignored') {
            return $value;
        }
        $variants = $value instanceof stdClass ? get_object_vars($value) : [];
        $variant = (string) array_key_first($variants);
        if (count($variants) !== 1 || ! in_array($variant, ['Set', 'Unsolicited', 'Unsigned'], true) || ! $check($variants[$variant])) {
            return null;
        }
        $inner = $variants[$variant];

        return [$variant => $inner instanceof stdClass ? ['rk' => $inner->rk ?? null] : $inner];
    }

    /**
     * SerialisableAttestationData; the certificates must be DER.
     *
     * @return string|array{0: string, 1: list<string>}|null
     */
    private static function attestationData(mixed $value): string|array|null
    {
        if (in_array($value, ['Self_', 'ECDAA', 'None', 'Uncertain'], true)) {
            return $value;
        }
        $variants = $value instanceof stdClass ? get_object_vars($value) : [];
        $variant = (string) array_key_first($variants);
        if (count($variants) !== 1 || ! in_array($variant, ['Basic', 'AttCa', 'AnonCa'], true) || ! is_array($variants[$variant])) {
            return null;
        }
        $certificates = [];
        foreach ($variants[$variant] as $certificate) {
            $der = Base64UrlSafe::decode($certificate);
            if ($der === null || @openssl_x509_read(Der::pem($der, 'CERTIFICATE')) === false) {
                return null;
            }
            $certificates[] = $der;
        }

        return [$variant, $certificates];
    }

    /**
     * AttestationMetadata, normalised as serde writes it again.
     *
     * @return array{mixed}|null The value in a list, null when it does not parse
     */
    private static function metadata(mixed $value): ?array
    {
        if ($value === 'None') {
            return ['None'];
        }
        $variants = $value instanceof stdClass ? get_object_vars($value) : [];
        $variant = (string) array_key_first($variants);
        $fields = $variants[$variant] ?? null;
        if (count($variants) !== 1 || ! $fields instanceof stdClass) {
            return null;
        }

        $normalised = match ($variant) {
            'Packed' => ($aaguid = self::uuid($fields->aaguid ?? null)) === null ? null : ['aaguid' => $aaguid],
            'Tpm' => ($aaguid = self::uuid($fields->aaguid ?? null)) === null || ! is_int($fields->firmware_version ?? null) || $fields->firmware_version < 0
                ? null : ['aaguid' => $aaguid, 'firmware_version' => $fields->firmware_version],
            'AndroidKey' => is_bool($fields->is_km_tee ?? null) && is_bool($fields->is_attest_tee ?? null)
                ? ['is_km_tee' => $fields->is_km_tee, 'is_attest_tee' => $fields->is_attest_tee] : null,
            'AndroidSafetyNet' => self::safetyNet($fields),
            default => null,
        };

        return $normalised === null ? null : [[$variant => $normalised]];
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function safetyNet(stdClass $fields): ?array
    {
        $digests = [];
        foreach (is_array($fields->apk_certificate_digest_sha256 ?? null) ? $fields->apk_certificate_digest_sha256 : [null] as $digest) {
            $bytes = Base64UrlSafe::decode($digest);
            if ($bytes === null) {
                return null;
            }
            $digests[] = Base64UrlSafe::encode($bytes);
        }
        $evaluation = $fields->evaluation_type ?? null;

        return is_string($fields->apk_package_name ?? null) && is_bool($fields->cts_profile_match ?? null) && is_bool($fields->basic_integrity ?? null)
            && ($evaluation === null || is_string($evaluation))
            ? ['apk_package_name' => $fields->apk_package_name, 'apk_certificate_digest_sha256' => $digests,
                'cts_profile_match' => $fields->cts_profile_match, 'basic_integrity' => $fields->basic_integrity, 'evaluation_type' => $evaluation]
            : null;
    }

    /**
     * A UUID as the uuid crate reads it (plain, hyphenated, braced or URN),
     * written back hyphenated in lower case.
     */
    public static function uuid(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }
        $hex = (string) preg_replace('/^(?:urn:uuid:|\{(?=.*\}$))|\}$/i', '', $value);
        if (preg_match('/^[0-9a-f]{32}$/i', $hex) !== 1 && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $hex) !== 1) {
            return null;
        }

        return self::formatUuid((string) hex2bin(str_replace('-', '', $hex)));
    }

    public static function formatUuid(string $bytes): string
    {
        $hex = bin2hex($bytes);

        return substr($hex, 0, 8).'-'.substr($hex, 8, 4).'-'.substr($hex, 12, 4).'-'.substr($hex, 16, 4).'-'.substr($hex, 20);
    }
}
