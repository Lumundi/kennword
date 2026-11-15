<?php

namespace App\Auth\Webauthn;

use App\Support\CborBytes;
use App\Support\CborMap;
use OpenSSLAsymmetricKey;

/**
 * The attestation statement formats of webauthn-rs-core's attestation.rs
 * that are ported: packed (with certificates or self attestation),
 * fido-u2f and apple. Each returns the parsed attestation data (a unit
 * variant, or a variant with the DER certificates) and the metadata.
 */
final class Attestation
{
    private const string OID_FIDO_AAGUID = '1.3.6.1.4.1.45724.1.1.4';

    private const string OID_BASIC_CONSTRAINTS = '2.5.29.19';

    private const string OID_APPLE_NONCE = '1.2.840.113635.100.8.2';

    /**
     * verify_packed_attestation
     *
     * @return array{string|array{0: string, 1: list<string>}, mixed}
     *
     * @throws WebauthnError
     */
    public static function packed(mixed $statement, AuthenticatorData $authData, string $clientDataHash): array
    {
        if (! $statement instanceof CborMap) {
            throw new WebauthnError('AttestationStatementMapInvalid');
        }
        $algValue = $statement->has('alg') ? $statement->get('alg') : throw new WebauthnError('AttestationStatementAlgMissing');
        $alg = is_int($algValue) ? array_search($algValue, CoseKey::ALGORITHMS, true) : throw new WebauthnError('AttestationStatementAlgInvalid');
        if (! is_string($alg)) {
            throw new WebauthnError('COSEKeyInvalidAlgorithm');
        }
        $signed = self::authDataBytes($authData).$clientDataHash;

        if ($statement->has('x5c')) {
            $certificates = self::certificates($statement->get('x5c'));
            $certificate = $certificates[0] ?? throw new WebauthnError('AttestationStatementX5CInvalid');
            if (! self::verifyWithCertificate($alg, $certificate, self::signature($statement), $signed)) {
                throw new WebauthnError('AttestationStatementSigInvalid');
            }
            self::assertPackedCertificate($certificate);

            // id-fido-gen-ce-aaguid, when present, must name the authenticator's AAGUID.
            $extension = (Der::certificateExtensions($certificate) ?? throw new WebauthnError('AttestationStatementX5CInvalid'))[self::OID_FIDO_AAGUID][0] ?? null;
            if ($extension !== null) {
                $aaguid = Der::single($extension['value'], 0x04) ?? throw new WebauthnError('AttestationStatementX5CInvalid');
                if ($aaguid !== $authData->aaguid) {
                    throw new WebauthnError('AttestationCertificateAAGUIDMismatch');
                }
            }

            return [['Basic', $certificates], ['Packed' => ['aaguid' => Credential::formatUuid($authData->aaguid)]]];
        }
        if ($statement->has('ecdaaKeyId')) {
            throw new WebauthnError('AttestationNotSupported');
        }

        // Self attestation: signed with the credential's own key.
        $key = CoseKey::fromCbor($authData->credentialKey);
        if ($alg !== $key->type) {
            throw new WebauthnError('AttestationStatementAlgMismatch');
        }
        if (! $key->verify(self::signature($statement), $signed)) {
            throw new WebauthnError('AttestationStatementSigInvalid');
        }

        return ['Self_', 'None'];
    }

    /**
     * verify_fidou2f_attestation: one certificate, whose key signed the U2F registration data.
     *
     * @return array{0: string, 1: list<string>}
     *
     * @throws WebauthnError
     */
    public static function fidoU2f(mixed $statement, AuthenticatorData $authData, string $clientDataHash): array
    {
        if (! $statement instanceof CborMap) {
            throw new WebauthnError('AttestationStatementMapInvalid');
        }
        $x5c = $statement->has('x5c') ? $statement->get('x5c') : throw new WebauthnError('AttestationStatementX5CMissing');
        $signature = $statement->get('sig');
        if (! $signature instanceof CborBytes) {
            throw new WebauthnError('AttestationStatementSigMissing');
        }
        if (! is_array($x5c) || count($x5c) !== 1) {
            throw new WebauthnError('AttestationStatementX5CInvalid');
        }
        $certificates = self::certificates($x5c);

        $key = CoseKey::fromCbor($authData->credentialKey);
        $signed = "\0".$authData->rpIdHash.$clientDataHash.$authData->credentialId.$key->x962();
        if (! self::verifyWithCertificate('ES256', $certificates[0], $signature->bytes, $signed)) {
            throw new WebauthnError('AttestationStatementSigInvalid');
        }

        return ['Basic', $certificates];
    }

    /**
     * verify_apple_anonymous_attestation: the certificate carries the nonce
     * of this registration and the credential's key.
     *
     * @return array{array{0: string, 1: list<string>}, string}
     *
     * @throws WebauthnError
     */
    public static function apple(mixed $statement, AuthenticatorData $authData, string $clientDataHash): array
    {
        if (! $statement instanceof CborMap) {
            throw new WebauthnError('AttestationStatementMapInvalid');
        }
        $x5c = $statement->has('x5c') ? $statement->get('x5c') : throw new WebauthnError('AttestationStatementX5CMissing');
        if (! is_array($x5c)) {
            throw new WebauthnError('AttestationStatementX5CInvalid');
        }
        $key = CoseKey::fromCbor($authData->credentialKey);
        $certificates = self::certificates($x5c);
        $certificate = $certificates[0] ?? throw new WebauthnError('AttestationStatementX5CInvalid');

        $extension = (Der::certificateExtensions($certificate) ?? throw new WebauthnError('AttestationStatementX5CInvalid'))[self::OID_APPLE_NONCE][0]
            ?? throw new WebauthnError('AttestationStatementMissingExtension');
        // SEQUENCE { [1] EXPLICIT OCTET STRING nonce }
        $nonce = Der::single(Der::single(Der::single($extension['value'], 0x30) ?? '', 0xA1) ?? '', 0x04);
        if ($nonce === null || strlen($nonce) !== 32) {
            throw new WebauthnError('AttestationStatementX5CInvalid');
        }
        if ($nonce !== hash('sha256', self::authDataBytes($authData).$clientDataHash, true)) {
            throw new WebauthnError('AttestationCertificateNonceMismatch');
        }

        if (! in_array($key->type, ['ES256', 'ES384', 'ES512'], true)) {
            throw new WebauthnError('COSEKeyInvalidType');
        }
        $details = openssl_pkey_get_details(self::certificateKey($certificate)) ?: [];
        $ec = is_array($details['ec'] ?? null) ? $details['ec'] : [];
        $sizes = ['prime256v1' => 32, 'secp384r1' => 48, 'secp521r1' => 66];
        $curves = ['prime256v1' => 'SECP256R1', 'secp384r1' => 'SECP384R1', 'secp521r1' => 'SECP521R1'];
        $name = is_string($ec['curve_name'] ?? null) ? $ec['curve_name'] : '';
        $x = is_string($ec['x'] ?? null) ? $ec['x'] : '';
        $y = is_string($ec['y'] ?? null) ? $ec['y'] : '';
        if (! isset($sizes[$name])) {
            throw new WebauthnError('ECDSACurveInvalidNid');
        }
        // BigNum::num_bytes drops leading zeros, which upstream then rejects.
        if (strlen($x) !== $sizes[$name] || strlen($y) !== $sizes[$name]) {
            throw new WebauthnError('COSEKeyECDSAXYInvalid');
        }
        if ($key->kind !== 'EC_EC2' || $key->curve !== $curves[$name] || $key->x !== $x || $key->y !== $y) {
            throw new WebauthnError('AttestationCredentialSubjectKeyMismatch');
        }

        return [['AnonCa', $certificates], 'None'];
    }

    /**
     * The raw authenticator data, which the attestation signs.
     */
    private static function authDataBytes(AuthenticatorData $authData): string
    {
        return $authData->raw;
    }

    /**
     * The x5c array as DER certificates OpenSSL reads.
     *
     * @return list<string>
     *
     * @throws WebauthnError
     */
    private static function certificates(mixed $x5c): array
    {
        if (! is_array($x5c)) {
            throw new WebauthnError('AttestationStatementX5CInvalid');
        }
        $certificates = [];
        foreach ($x5c as $item) {
            if (! $item instanceof CborBytes) {
                throw new WebauthnError('AttestationStatementX5CInvalid');
            }
            self::certificateKey($item->bytes);
            $certificates[] = $item->bytes;
        }

        return $certificates;
    }

    /**
     * @throws WebauthnError
     */
    private static function signature(CborMap $statement): string
    {
        if (! $statement->has('sig')) {
            throw new WebauthnError('AttestationStatementSigMissing');
        }
        $signature = $statement->get('sig');

        return $signature instanceof CborBytes ? $signature->bytes : throw new WebauthnError('CBORInvalidType');
    }

    /**
     * @throws WebauthnError
     */
    private static function certificateKey(string $der): OpenSSLAsymmetricKey
    {
        // OpenSSL warns about what it cannot read, and Laravel would turn the
        // warning into a 500; Vaultwarden answers a client's bad certificate
        // with its Webauthn error.
        $certificate = @openssl_x509_read(Der::pem($der, 'CERTIFICATE')) ?: throw new WebauthnError('OpenSSLError');

        return @openssl_pkey_get_public($certificate) ?: throw new WebauthnError('OpenSSLError');
    }

    /**
     * verify_signature with the certificate's public key.
     *
     * @throws WebauthnError
     */
    private static function verifyWithCertificate(string $alg, string $der, string $signature, string $data): bool
    {
        $key = self::certificateKey($der);
        $raw = null;
        if ($alg === 'EDDSA') {
            // The raw Ed25519 key ends the SubjectPublicKeyInfo.
            $pem = openssl_pkey_get_details($key)['key'] ?? '';
            $spki = base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', is_string($pem) ? $pem : ''), true);
            $raw = is_string($spki) ? substr($spki, -32) : null;
        }

        return CoseKey::verifyWith($alg, $key, $signature, $data, $raw);
    }

    /**
     * assert_packed_attest_req: version 3; country, organisation, common name
     * and the unit "Authenticator Attestation" in the subject; not a CA; the
     * AAGUID extension, if any, not critical.
     *
     * @throws WebauthnError
     */
    private static function assertPackedCertificate(string $der): void
    {
        $parsed = @openssl_x509_parse(Der::pem($der, 'CERTIFICATE'), false) ?: throw new WebauthnError('AttestationStatementX5CInvalid');
        $subject = is_array($parsed['subject'] ?? null) ? $parsed['subject'] : [];
        $first = static fn (string $name): mixed => is_array($subject[$name] ?? null) ? ($subject[$name][0] ?? null) : ($subject[$name] ?? null);
        if (($parsed['version'] ?? null) !== 2 || $first('countryName') === null || $first('organizationName') === null || $first('commonName') === null
            || $first('organizationalUnitName') !== 'Authenticator Attestation') {
            throw new WebauthnError('AttestationCertificateRequirementsNotMet');
        }

        $extensions = Der::certificateExtensions($der) ?? throw new WebauthnError('AttestationCertificateRequirementsNotMet');
        $aaguid = $extensions[self::OID_FIDO_AAGUID] ?? [];
        if (count($aaguid) > 1 || ($aaguid[0]['critical'] ?? false)) {
            throw new WebauthnError('AttestationCertificateRequirementsNotMet');
        }
        $constraints = $extensions[self::OID_BASIC_CONSTRAINTS] ?? [];
        $sequence = count($constraints) === 1 ? Der::items(Der::single($constraints[0]['value'], 0x30) ?? "\xFF") : null;
        $isCa = $sequence !== null && ($sequence[0]['tag'] ?? null) === 0x01 && $sequence[0]['content'] !== "\0";
        if ($sequence === null || $isCa) {
            throw new WebauthnError('AttestationCertificateRequirementsNotMet');
        }
    }
}
