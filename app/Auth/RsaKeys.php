<?php

namespace App\Auth;

use App\Config\Config;
use App\Support\PrivateFile;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * The RSA key that signs Vaultwarden's tokens (auth::initialize_keys), shared
 * with Vaultwarden through the same file: data/rsa_key.pem by default.
 */
final class RsaKeys
{
    private ?string $pem = null;

    private ?OpenSSLAsymmetricKey $private = null;

    private ?OpenSSLAsymmetricKey $public = null;

    public function __construct(
        private readonly Config $config,
    ) {}

    public function privateKey(): OpenSSLAsymmetricKey
    {
        return $this->private ??= openssl_pkey_get_private($this->pem())
            ?: throw new RuntimeException("The private key {$this->path()} is not a valid RSA key.");
    }

    public function publicKey(): OpenSSLAsymmetricKey
    {
        if ($this->public === null) {
            $details = openssl_pkey_get_details($this->privateKey());
            $pem = is_array($details) && is_string($details['key'] ?? null) ? $details['key'] : '';
            $this->public = openssl_pkey_get_public($pem) ?: throw new RuntimeException('Cannot derive the public key.');
        }

        return $this->public;
    }

    /**
     * An index in 0..$length derived from the email, the same for every request
     * (auth::prelogin_kdf_index). The key is derived from the PEM file, so it
     * stays the same across restarts and matches Vaultwarden's.
     */
    public function preloginKdfIndex(string $email, int $length): int
    {
        $key = hash_hmac('sha256', 'prelogin-kdf', $this->pem(), true);
        $tag = hash_hmac('sha256', $email, $key, true);

        return ((ord($tag[0]) << 8) | ord($tag[1])) % $length;
    }

    /**
     * The key that signs what requests hand to the notifications daemon
     * (App\Notifications\Channel), which reads the same key file.
     */
    public function notificationsKey(): string
    {
        return hash_hmac('sha256', 'notifications', $this->pem(), true);
    }

    /**
     * The PEM file as stored, created with a new 2048-bit key when missing.
     */
    private function pem(): string
    {
        if ($this->pem !== null) {
            return $this->pem;
        }

        $path = $this->path();
        $pem = is_file($path) ? file_get_contents($path) : false;
        if ($pem === false) {
            $pem = self::generate();
            // Exclusive creation, so concurrent first requests agree on one key. Whoever reads it can sign
            // tokens for every account, so only its owner may.
            if (! PrivateFile::create($path, $pem)) {
                $pem = file_get_contents($path) ?: throw new RuntimeException("Cannot create the private key {$path}.");
            }
        }

        return $this->pem = $pem;
    }

    private function path(): string
    {
        return $this->config->absolutePath($this->config->privateRsaKey());
    }

    /**
     * A new key in the PKCS#1 PEM format OpenSSL's `private_key_to_pem` writes.
     */
    private static function generate(): string
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($key === false || ! openssl_pkey_export($key, $pkcs8) || ! is_string($pkcs8)) {
            throw new RuntimeException('Cannot generate an RSA key: '.openssl_error_string());
        }

        $der = base64_decode((string) preg_replace('/-----[A-Z ]+-----|\s/', '', $pkcs8), true);
        $pkcs1 = self::pkcs1FromPkcs8((string) $der);

        return "-----BEGIN RSA PRIVATE KEY-----\n".chunk_split(base64_encode($pkcs1), 64, "\n")."-----END RSA PRIVATE KEY-----\n";
    }

    /**
     * The RSAPrivateKey inside a PKCS#8 PrivateKeyInfo:
     * SEQUENCE { version INTEGER, algorithm SEQUENCE, privateKey OCTET STRING }.
     */
    private static function pkcs1FromPkcs8(string $der): string
    {
        $offset = 0;
        self::readElement($der, $offset, 0x30, enter: true);
        self::readElement($der, $offset, 0x02);
        self::readElement($der, $offset, 0x30);

        return self::readElement($der, $offset, 0x04);
    }

    /**
     * Read one DER element of the expected tag and return its content; when
     * entering a constructed element, the offset moves to its first child.
     */
    private static function readElement(string $der, int &$offset, int $tag, bool $enter = false): string
    {
        if (! isset($der[$offset + 1]) || ord($der[$offset]) !== $tag) {
            throw new RuntimeException('Unexpected structure of the generated key.');
        }

        $length = ord($der[$offset + 1]);
        $offset += 2;
        if ($length & 0x80) {
            $bytes = $length & 0x7F;
            $length = 0;
            for ($i = 0; $i < $bytes; $i++) {
                $length = ($length << 8) | ord($der[$offset + $i]);
            }
            $offset += $bytes;
        }

        $content = substr($der, $offset, $length);
        if (! $enter) {
            $offset += $length;
        }

        return $content;
    }
}
