<?php

namespace Tests\Unit\Auth;

use App\Auth\Sso\AuthenticatedUser;
use App\Auth\Sso\Jws;
use App\Auth\Sso\Sso;
use App\Http\ApiError;
use App\Support\FormUrlencoded;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * The parts of the SSO login that need no provider: the signatures of its
 * tokens, the stored form of the authenticated user and the encodings.
 */
class SsoTest extends TestCase
{
    public function test_rsa_and_ec_signatures(): void
    {
        foreach ([['RS256', OPENSSL_KEYTYPE_RSA, null, 'sha256'], ['ES256', OPENSSL_KEYTYPE_EC, 'prime256v1', 'sha256'],
            ['ES384', OPENSSL_KEYTYPE_EC, 'secp384r1', 'sha384']] as [$algorithm, $type, $curve, $hash]) {
            $key = openssl_pkey_new(array_filter(['private_key_type' => $type, 'private_key_bits' => 2048, 'curve_name' => $curve]));
            $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
            [$token, $jwk] = $this->signed($algorithm, $key, $hash);

            $jws = Jws::parse($token);
            $this->assertNotNull($jws);
            $this->assertSame($algorithm, $jws->algorithm());
            $this->assertSame([$jwk], Jws::filterKeys([$jwk], 'key-1', $algorithm));
            $this->assertSame([], Jws::filterKeys([$jwk], 'other', $algorithm));
            $this->assertTrue($jws->verify($algorithm, $jwk), $algorithm);

            $tampered = Jws::parse(substr($token, 0, -4).(str_ends_with($token, 'AAAA') ? 'BBBB' : 'AAAA'));
            $this->assertFalse($tampered?->verify($algorithm, $jwk) ?? false, $algorithm);
        }
    }

    /**
     * Signatures made by the OpenSSL command line tool, with a salt as long as
     * the hash (rsa_pss_saltlen:-1), which the rsa crate requires, and one of
     * 20 bytes, which it refuses.
     */
    public function test_rsa_pss_signatures(): void
    {
        $jwk = (object) ['kty' => 'RSA', 'kid' => 'key-1', 'e' => 'AQAB', 'n' => '65RC8fSAm2FLG3mT59RgzPrMReP9QyppTOOKCMLeQOLCqznz0bPlqnp8_HwGaToh28j2fMeOANJ3F0'
            .'MAZrrlQGylBj6mbjpn5A0wpXyhqc6WNtJnuaOKJYHkDdWdD0b8ONtxp6GTOqgFAIOu9_pSdbMkgkjgEyozTFCSYWu_DAVnxqem7kuBr3pgXwWF5JheyizQFfgpR4a7oE37dWLbCUfQI'
            .'O2iypfYrVr7duTyRFL_2N0cagwKmD4vWC0KJ6ei0ATF1tR1_YCC9tdfTZrGHMtsye8qJXPr08HvCGiVtx48Rqs13NQHoNr0gAU_LbqjXri5mIomZXBbKsdfngj7wQ'];
        $input = 'eyJhbGciOiJQUzI1NiIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiIxIn0';
        $hashLong = 'du0KmA88x6RKzHzWOFDOMQp87HWstPODrKf59es5IpnY1iKtk94FjH3bNfgOj7DulgIZjgowoiKSpUJZjUcOtSINnnkaeKmSbC6iS03U2uAs22_E47Z_8oh22kA9mARimj6twgD19X'
            .'IWwMrMRT1fDk5sTseLRJI1jVfWZesMnm5qdjdycEINbGd5l5anGIKTUZrcF4opcr6VGRSHisUSG3pSdAUQlBhfCZ1dgbT09q6ChGHqybjqc4x0lbYPUJu2dQDfiPSvHBFmPXMY6q0hi1II'
            .'pUq4FwXbaNN09EJTw_B438VCVEzxx3jHDWPDF1QK0cp0fxpn3NrvNRe1AoruOw';
        $short = 'QzRcF1klu60FkSaEeEB7FSHSvFr1lQLigHS8G0ePavQZnkG3P9oRzt4gDa7Zd83FgtE6BuVBYBkZ4vIfUdP7mkFH9mGsa2SYgxEgsI9yADQBEbk8FKjxzo-wu_NWhEjXhuEhxJd5YQi'
            .'PCqZIx9zrl3teH4JwIiHe93Tdryo9KkmvF1ppeZnKa6qIJE_-cWK9Gc-iv0T0Osrz3lOtxqReESnfYbaoB9oO5cUdhYbzAIvOI6rVzV4Tj3Sbe3hOAergJ1aFm2HaDh2GDIbr55H3q1z'
            .'weAUAJgM7Iro5o_9yxs9NW8qdqkX1eozDFajgY2Hk4toMOf3sIJulrp-fvRfnGQ';

        $jws = Jws::parse("{$input}.{$hashLong}");
        $this->assertNotNull($jws);
        $this->assertSame([$jwk], Jws::filterKeys([$jwk], 'key-1', 'PS256'));
        $this->assertTrue($jws->verify('PS256', $jwk));
        $this->assertFalse($jws->verify('PS384', $jwk));
        $this->assertFalse($jws->verify('RS256', $jwk));
        $this->assertFalse(Jws::parse("{$input}.{$short}")?->verify('PS256', $jwk) ?? true);
        $this->assertFalse(Jws::parse('eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiIxIn0.'.$hashLong)?->verify('PS256', $jwk) ?? true);
    }

    /**
     * openidconnect verifies RSA keys of up to 4096 bits and no P-521 signatures.
     */
    public function test_keys_openidconnect_does_not_take(): void
    {
        $large = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4104]);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $large);
        [$token, $jwk] = $this->signed('RS256', $large, 'sha256');
        $this->assertFalse(Jws::parse($token)?->verify('RS256', $jwk) ?? true);
        $this->assertSame(1, openssl_verify(...$this->opensslArguments($token, $large)));

        $p521 = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1']);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $p521);
        [$token, $jwk] = $this->signed('ES512', $p521, 'sha512');
        $this->assertSame([$jwk], Jws::filterKeys([$jwk], 'key-1', 'ES512'));
        $this->assertFalse(Jws::parse($token)?->verify('ES512', $jwk) ?? true);
    }

    /**
     * openidconnect puts x and y behind 0x04 without checking them one by one,
     * so only the length of the point counts.
     */
    public function test_ec_coordinates_count_together(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        [$token, $jwk] = $this->signed('ES256', $key, 'sha256');
        $jws = Jws::parse($token);
        $this->assertNotNull($jws);
        $this->assertIsString($jwk->x);
        $this->assertIsString($jwk->y);
        $point = (string) Jws::base64UrlDecode($jwk->x).(string) Jws::base64UrlDecode($jwk->y);

        $split = static fn (int $at): object => (object) [...(array) $jwk, 'x' => rtrim(strtr(base64_encode(substr($point, 0, $at)), '+/', '-_'), '='),
            'y' => rtrim(strtr(base64_encode(substr($point, $at)), '+/', '-_'), '=')];
        $this->assertTrue($jws->verify('ES256', $split(31)));
        $this->assertTrue($jws->verify('ES256', $split(0)));
        $this->assertFalse($jws->verify('ES256', (object) [...(array) $jwk, 'y' => rtrim(strtr(base64_encode(substr($point, 32, 31)), '+/', '-_'), '=')]));
    }

    public function test_shared_secret_and_eddsa_signatures(): void
    {
        $input = $this->base64('{"alg":"HS256"}').'.'.$this->base64('{"sub":"1"}');
        $jws = Jws::parse($input.'.'.$this->base64(hash_hmac('sha256', $input, 'secret', true)));
        $this->assertNotNull($jws);
        $this->assertTrue(Jws::usesSharedSecret('HS256'));
        $this->assertTrue($jws->verify('HS256', 'secret'));
        $this->assertFalse($jws->verify('HS256', 'other'));

        $pair = sodium_crypto_sign_keypair();
        $input = $this->base64('{"alg":"EdDSA"}').'.'.$this->base64('{"sub":"1"}');
        $jws = Jws::parse($input.'.'.$this->base64(sodium_crypto_sign_detached($input, sodium_crypto_sign_secretkey($pair))));
        $this->assertNotNull($jws);
        $jwk = (object) ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $this->base64(sodium_crypto_sign_publickey($pair))];
        $this->assertTrue($jws->verify('EdDSA', $jwk));

        // Keys for encryption only, or for another algorithm, do not sign.
        $this->assertSame([], Jws::filterKeys([(object) ['kty' => 'RSA', 'use' => 'enc']], null, 'RS256'));
        $this->assertSame([], Jws::filterKeys([(object) ['kty' => 'RSA', 'alg' => 'RS512']], null, 'RS256'));
        $this->assertNull(Jws::parse('a.b'));
    }

    public function test_the_authenticated_user_is_stored_like_serde_writes_it(): void
    {
        $user = new AuthenticatedUser('refresh', 'access', 3600, 'https://idp/sub', 'judy@example.com', true, 'Judy');
        $json = '{"refresh_token":"refresh","access_token":"access","expires_in":{"secs":3600,"nanos":0},'
            .'"identifier":"https://idp/sub","email":"judy@example.com","email_verified":true,"user_name":"Judy"}';
        $this->assertSame($json, $user->toJson());
        $this->assertEquals($user, AuthenticatedUser::fromJson($json));

        $sparse = new AuthenticatedUser(null, 'access', null, 'id', 'judy@example.com', null, null);
        $this->assertEquals($sparse, AuthenticatedUser::fromJson($sparse->toJson()));
        $this->assertNull(AuthenticatedUser::fromJson('{"access_token":1}'));
    }

    public function test_the_state_is_strict_base64(): void
    {
        $this->assertSame('state', Sso::decodeState(base64_encode('state')));
        foreach (['%%' => 'Failed to decode %% using base64', 'c3RhdGU' => 'Failed to decode c3RhdGU using base64',
            'c3RhdGV=' => 'Failed to decode c3RhdGV= using base64', base64_encode("\xff") => 'Invalid utf8 chars in /w== after base64 decoding'] as $state => $message) {
            try {
                Sso::decodeState($state);
                $this->fail("{$state} decoded.");
            } catch (ApiError $error) {
                $this->assertSame($message, $error->getMessage());
            }
        }
    }

    public function test_form_encoding_of_the_redirects(): void
    {
        $this->assertSame([['a', 'b c'], ['d', ''], ['e', 'f=g']], FormUrlencoded::parse('a=b+c&&d&e=f%3Dg'));
        $this->assertSame('https://idp/authorize?x=1&state=c3%3D&scope=openid+email#top',
            FormUrlencoded::appendPairs('https://idp/authorize?x=1#top', [['state', 'c3='], ['scope', 'openid email']]));
        $this->assertSame('bitwarden://sso-callback?code=1', FormUrlencoded::appendPairs('bitwarden://sso-callback', [['code', '1']]));
    }

    /**
     * @return array{string, stdClass} The token and the JWK of its key
     */
    private function signed(string $algorithm, OpenSSLAsymmetricKey $key, string $hash): array
    {
        $input = $this->base64((string) json_encode(['alg' => $algorithm, 'kid' => 'key-1'])).'.'.$this->base64('{"sub":"1"}');
        $this->assertTrue(openssl_sign($input, $signature, $key, $hash));
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);

        if (str_starts_with($algorithm, 'RS')) {
            $jwk = (object) ['kty' => 'RSA', 'kid' => 'key-1', 'n' => $this->part($details, 'rsa', 'n'), 'e' => $this->part($details, 'rsa', 'e')];
        } else {
            // A DER signature becomes the raw r and s of JWS.
            [$size, $curve] = ['ES256' => [32, 'P-256'], 'ES384' => [48, 'P-384'], 'ES512' => [66, 'P-521']][$algorithm] ?? [0, ''];
            $signature = $this->rawEcSignature(is_string($signature) ? $signature : '', $size);
            $jwk = (object) ['kty' => 'EC', 'kid' => 'key-1', 'crv' => $curve,
                'x' => $this->base64(str_pad((string) base64_decode(strtr($this->part($details, 'ec', 'x'), '-_', '+/')), $size, "\0", STR_PAD_LEFT)),
                'y' => $this->base64(str_pad((string) base64_decode(strtr($this->part($details, 'ec', 'y'), '-_', '+/')), $size, "\0", STR_PAD_LEFT))];
        }

        return [$input.'.'.$this->base64(is_string($signature) ? $signature : ''), $jwk];
    }

    /**
     * The arguments of openssl_verify() for an RS256 token and its key.
     *
     * @return array{string, string, OpenSSLAsymmetricKey, string}
     */
    private function opensslArguments(string $token, OpenSSLAsymmetricKey $key): array
    {
        [$header, $payload, $signature] = explode('.', $token);
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        $this->assertIsString($details['key'] ?? null);
        $public = openssl_pkey_get_public($details['key']);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $public);

        return ["{$header}.{$payload}", (string) base64_decode(strtr($signature, '-_', '+/')), $public, 'sha256'];
    }

    /**
     * A number of the key details, base64url encoded.
     *
     * @param  array<mixed>  $details
     */
    private function part(array $details, string $type, string $name): string
    {
        $value = is_array($details[$type] ?? null) ? ($details[$type][$name] ?? null) : null;
        $this->assertIsString($value);

        return $this->base64($value);
    }

    private function rawEcSignature(string $der, int $size): string
    {
        $offset = 2;
        $raw = '';
        for ($i = 0; $i < 2; $i++) {
            $length = ord($der[$offset + 1]);
            $raw .= str_pad(ltrim(substr($der, $offset + 2, $length), "\0"), $size, "\0", STR_PAD_LEFT);
            $offset += 2 + $length;
        }

        return $raw;
    }

    private function base64(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
