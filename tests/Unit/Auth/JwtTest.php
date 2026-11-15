<?php

namespace Tests\Unit\Auth;

use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\RsaKeys;
use App\Config\Config;
use App\Http\ApiError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Attributes\Parity;

/**
 * auth::encode_jwt / decode_jwt and the key handling of auth::initialize_keys.
 */
class JwtTest extends TestCase
{
    private const int NOW = 1_800_000_000;

    private string $base;

    private RsaKeys $keys;

    private Jwt $jwt;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/vw-jwt-'.bin2hex(random_bytes(6));
        mkdir($this->base.'/data', recursive: true);

        $config = Config::load(static fn (string $key): ?string => ['DOMAIN' => 'https://vault.example.com/base'][$key] ?? null, $this->base);
        $this->keys = new RsaKeys($config);
        $this->jwt = new Jwt($this->keys, $config);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));
    }

    public function test_a_missing_key_is_created_like_vaultwarden_does(): void
    {
        $this->keys->privateKey();

        $pem = (string) file_get_contents("{$this->base}/data/rsa_key.pem");
        $this->assertStringStartsWith("-----BEGIN RSA PRIVATE KEY-----\n", $pem);
        // Whoever reads it can sign tokens for every account, so only its owner may.
        $this->assertSame(0600, fileperms("{$this->base}/data/rsa_key.pem") & 0777);
        $this->assertStringEndsWith("\n-----END RSA PRIVATE KEY-----\n", $pem);

        $details = openssl_pkey_get_details($this->keys->privateKey());
        $this->assertIsArray($details);
        $this->assertSame(2048, $details['bits']);
        $this->assertSame(OPENSSL_KEYTYPE_RSA, $details['type']);

        // A second instance reads the same key instead of creating another one.
        $config = Config::load(static fn (string $key): ?string => ['DOMAIN' => 'https://vault.example.com'][$key] ?? null, $this->base);
        $token = $this->jwt->encode($this->claims());
        $this->assertSame($this->claims(), (new Jwt(new RsaKeys($config), $config))->decode($token, JwtIssuer::Admin, self::NOW));
        $this->assertSame($pem, file_get_contents("{$this->base}/data/rsa_key.pem"));
    }

    #[Parity('config:RSA_KEY_FILENAME')]
    public function test_the_key_lives_at_rsa_key_filename(): void
    {
        $file = "{$this->base}/keys/token";
        mkdir("{$this->base}/keys");
        $config = Config::load(static fn (string $key): ?string => ['RSA_KEY_FILENAME' => $file][$key] ?? null, $this->base);
        (new RsaKeys($config))->privateKey();

        $this->assertFileExists("{$file}.pem");
        $this->assertFileDoesNotExist("{$this->base}/data/rsa_key.pem");
    }

    public function test_tokens_have_rockets_header_and_keep_the_claim_order(): void
    {
        $token = $this->jwt->encode($this->claims());
        [$header, $payload, $signature] = explode('.', $token);

        $this->assertSame('{"typ":"JWT","alg":"RS256"}', base64_decode(strtr($header, '-_', '+/')));
        $this->assertSame(
            '{"nbf":1800000000,"exp":1800001200,"iss":"https://vault.example.com|admin","sub":"admin_panel","name":"Jürgen / Ünal"}',
            base64_decode(strtr($payload, '-_', '+/')),
        );
        $this->assertStringNotContainsString('=', $signature);
        $this->assertSame(1, openssl_verify("{$header}.{$payload}", (string) base64_decode(strtr($signature, '-_', '+/')), $this->keys->publicKey(), OPENSSL_ALGO_SHA256));
    }

    public function test_decoding_returns_the_claims_and_ignores_whitespace(): void
    {
        $token = $this->jwt->encode($this->claims());

        $this->assertSame($this->claims(), $this->jwt->decode(" {$token}\n", JwtIssuer::Admin, self::NOW));
    }

    public function test_leeway_of_thirty_seconds(): void
    {
        $token = $this->jwt->encode($this->claims(nbf: self::NOW + 30, exp: self::NOW - 30));

        $this->assertSame('admin_panel', $this->jwt->decode($token, JwtIssuer::Admin, self::NOW)['sub']);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidClaims(): iterable
    {
        yield 'expired' => [['exp' => self::NOW - 31], 'Token has expired'];
        yield 'not yet valid' => [['nbf' => self::NOW + 31], 'Error decoding JWT: Error(ImmatureSignature)'];
        yield 'other issuer' => [['iss' => 'https://vault.example.com|login'], 'Issuer is invalid'];
        yield 'other domain' => [['iss' => 'https://other.example.com|admin'], 'Issuer is invalid'];
        yield 'missing exp' => [['exp' => null], 'Error decoding JWT: Error(MissingRequiredClaim("exp"))'];
        yield 'audience' => [['aud' => 'clients'], 'Error decoding JWT: Error(InvalidAudience)'];
    }

    /**
     * @param  array<string, mixed>  $changes
     */
    #[DataProvider('invalidClaims')]
    public function test_invalid_claims_are_refused(array $changes, string $message): void
    {
        $token = $this->jwt->encode(array_filter([...$this->claims(), ...$changes], static fn (mixed $value): bool => $value !== null));

        $this->assertDecodingFails($token, $message);
    }

    public function test_malformed_tokens_are_refused(): void
    {
        $token = $this->jwt->encode($this->claims());
        [$header, $payload, $signature] = explode('.', $token);
        $otherPayload = rtrim(strtr(base64_encode('{"exp":1900000000,"iss":"https://vault.example.com|admin","sub":"admin_panel"}'), '+/', '-_'), '=');

        $this->assertDecodingFails("{$header}.{$payload}", 'Token is invalid');
        $this->assertDecodingFails("{$header}.{$otherPayload}.{$signature}", 'Error decoding JWT: Error(InvalidSignature)');
        $this->assertDecodingFails("{$header}.{$payload}.{$signature}=", 'Error decoding JWT: Error(Base64)');

        // The unused bits of the last character must be zero, as in the base64 crate.
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $last = strpos($alphabet, $signature[-1]);
        $this->assertIsInt($last);
        $this->assertDecodingFails("{$header}.{$payload}.".substr($signature, 0, -1).$alphabet[$last | 1], 'Error decoding JWT: Error(Base64)');

        $hs256 = rtrim(strtr(base64_encode('{"typ":"JWT","alg":"HS256"}'), '+/', '-_'), '=');
        $this->assertDecodingFails("{$hs256}.{$payload}.{$signature}", 'Error decoding JWT: Error(InvalidAlgorithm)');
    }

    public function test_the_prelogin_index_is_derived_from_the_key_file(): void
    {
        $this->keys->privateKey();
        $pem = (string) file_get_contents("{$this->base}/data/rsa_key.pem");

        $tag = hash_hmac('sha256', 'user@example.com', hash_hmac('sha256', 'prelogin-kdf', $pem, true), true);
        $unpacked = unpack('n', $tag);
        $this->assertIsArray($unpacked);
        $this->assertIsInt($unpacked[1]);

        $this->assertSame($unpacked[1] % 7, $this->keys->preloginKdfIndex('user@example.com', 7));
        $this->assertSame($this->keys->preloginKdfIndex('user@example.com', 7), $this->keys->preloginKdfIndex('user@example.com', 7));
    }

    /**
     * @return array<string, mixed>
     */
    private function claims(int $nbf = self::NOW, int $exp = self::NOW + 1200): array
    {
        return ['nbf' => $nbf, 'exp' => $exp, 'iss' => 'https://vault.example.com|admin', 'sub' => 'admin_panel', 'name' => 'Jürgen / Ünal'];
    }

    private function assertDecodingFails(string $token, string $message): void
    {
        try {
            $this->jwt->decode($token, JwtIssuer::Admin, self::NOW);
            $this->fail("Decoding should fail with: {$message}");
        } catch (ApiError $error) {
            $this->assertSame($message, $error->getMessage());
        }
    }
}
