<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Device;
use App\Models\TwoFactor;
use App\Models\User;
use App\Support\Random;
use Illuminate\Http\Response;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\Support\SoftwareAuthenticator;
use Tests\TestCase;

/**
 * Security keys as a second factor (src/api/core/two_factor/webauthn.rs),
 * with a software authenticator.
 */
class WebauthnTest extends TestCase
{
    use UsesVaultwardenDatabase;

    private const string DEVICE = '0b7f4e5c-1d2a-4b3c-8d9e-0f1a2b3c4d5e';

    private User $user;

    /**
     * @var array<string, string>
     */
    private array $session;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000', 'LOGIN_RATELIMIT_MAX_BURST' => '100'];
    }

    #[DataProvider('drivers')]
    public function test_registration_and_login(string $driver): void
    {
        $this->signUp($driver);
        $setup = $this->postJson('/api/two-factor/get-webauthn', ['masterPasswordHash' => 'client-hash'], $this->session)
            ->assertStatus(200)->assertJsonPath('webAuthn', ['enabled' => false, 'keys' => []]);
        $token = $setup->json('userVerificationToken');

        $challenge = $this->postJson('/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => $token], $this->session)->assertStatus(200);
        $options = $this->arrayOf($challenge->json('options'));
        $this->assertSame(['attestation', 'authenticatorSelection', 'challenge', 'errorMessage', 'excludeCredentials', 'pubKeyCredParams', 'rp',
            'status', 'timeout', 'user'], array_keys($options));
        $this->assertSame(['id' => 'localhost', 'name' => 'http://localhost'], $options['rp']);
        $this->assertSame(['displayName' => 'Judy', 'id' => SoftwareAuthenticator::base64((string) hex2bin(str_replace('-', '', $this->user->uuid))),
            'name' => 'judy@example.com'], $options['user']);
        $this->assertSame(['requireResidentKey' => false, 'residentKey' => 'discouraged', 'userVerification' => 'discouraged'], $options['authenticatorSelection']);
        $this->assertSame([['alg' => -7, 'type' => 'public-key'], ['alg' => -257, 'type' => 'public-key']], $options['pubKeyCredParams']);
        $this->assertSame([60000, [], 'ok', ''], [$options['timeout'], $options['excludeCredentials'], $options['status'], $options['errorMessage']]);
        $state = TwoFactor::findByUserAndType($this->user->uuid, TwoFactor::TYPE_WEBAUTHN_REGISTER_CHALLENGE)->data ?? '';
        $this->assertStringStartsWith('{"rs":{"allow_synchronised_authenticators":true,"authenticator_attachment":null,"challenge":"', $state);
        $this->assertStringEndsWith('","credential_algorithms":["ES256","RS256"],"exclude_credentials":[],"extensions":{},"policy":"discouraged","require_resident_key":false}}', $state);

        $key = new SoftwareAuthenticator;
        $activate = ['id' => 1, 'name' => 'First key', 'userVerificationToken' => $token];
        $this->postJson('/api/two-factor/webauthn', [...$activate, 'deviceResponse' => $key->register($options, origin: 'https://evil.example')], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Webauthn');
        // The failed attempt used up the challenge.
        $this->postJson('/api/two-factor/webauthn', [...$activate, 'deviceResponse' => $key->register($options)], $this->session)
            ->assertStatus(400)->assertJsonPath('message', "Can't recover challenge");
        // A certificate OpenSSL cannot read is the client's error, not the server's.
        $this->postJson('/api/two-factor/webauthn', [...$activate, 'deviceResponse' => $key->register($this->challenge($token), 'packed-garbage-x5c')], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Webauthn');

        $options = $this->challenge($token);
        $this->postJson('/api/two-factor/webauthn', [...$activate, 'deviceResponse' => $key->register($options)], $this->session)
            ->assertStatus(200)->assertExactJson(['webAuthn' => ['enabled' => true, 'keys' => [['id' => 1, 'migrated' => false, 'name' => 'First key']]]]);
        $stored = $this->stored();
        $this->assertSame(['id', 'name', 'migrated', 'credential'], array_keys($this->arrayOf($stored[0] ?? null)));
        $credential = $this->arrayOf(data_get($stored, '0.credential.cred'));
        $this->assertSame(['cred_id', 'cred', 'counter', 'transports', 'user_verified', 'backup_eligible', 'backup_state', 'registration_policy',
            'extensions', 'attestation', 'attestation_format'], array_keys($credential));
        $this->assertSame([SoftwareAuthenticator::base64($key->credentialId), 'ES256', 'SECP256R1', 0, null, 'discouraged', 'none'],
            [$credential['cred_id'], data_get($credential, 'cred.type_'), data_get($credential, 'cred.key.EC_EC2.curve'), $credential['counter'],
                $credential['transports'], $credential['registration_policy'], $credential['attestation_format']]);
        $this->assertSame(['cred_protect' => 'NotRequested', 'hmac_create_secret' => 'NotRequested', 'appid' => 'NotRequested', 'cred_props' => 'NotRequested'],
            $credential['extensions']);
        $this->assertSame(['data' => 'None', 'metadata' => 'None'], $credential['attestation']);

        // The other formats; the token of the disabled state no longer fits.
        $this->postJson('/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => $token], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Invalid verification token: Invalid state');
        $keys = ['packed' => new SoftwareAuthenticator, 'packed-x5c' => new SoftwareAuthenticator, 'fido-u2f' => new SoftwareAuthenticator];
        $id = 2;
        foreach ($keys as $format => $other) {
            $token = $this->postJson('/api/two-factor/get-webauthn', ['masterPasswordHash' => 'client-hash'], $this->session)->json('userVerificationToken');
            $this->postJson('/api/two-factor/webauthn', ['id' => $id, 'name' => $format, 'userVerificationToken' => $token,
                'deviceResponse' => $other->register($this->challenge($token), $format)], $this->session)->assertStatus(200)->assertJsonPath('webAuthn.keys.'.($id - 1).'.name', $format);
            $id++;
        }
        $this->assertSame([['None', 'None', 'none'], ['Self_', 'None', 'packed'], ['Basic', 'Packed', 'packed'], ['Basic', 'None', 'fido-u2f']],
            array_map(static fn (mixed $registration): array => [
                is_array(data_get($registration, 'credential.cred.attestation.data')) ? 'Basic' : data_get($registration, 'credential.cred.attestation.data'),
                is_array(data_get($registration, 'credential.cred.attestation.metadata')) ? 'Packed' : data_get($registration, 'credential.cred.attestation.metadata'),
                data_get($registration, 'credential.cred.attestation_format')], $this->stored()));

        // Logins with any of the keys.
        $prompt = $this->login()->assertStatus(400);
        $request = $this->arrayOf($prompt->json('TwoFactorProviders2.7'));
        $this->assertSame(['allowCredentials', 'challenge', 'extensions', 'rpId', 'timeout', 'userVerification'], array_keys($request));
        $this->assertSame([['appid' => 'http://localhost/app-id.json'], 'localhost', 60000, 'discouraged'],
            [$request['extensions'], $request['rpId'], $request['timeout'], $request['userVerification']]);
        $this->assertCount(4, $this->arrayOf($request['allowCredentials']));

        $this->login(['two_factor_provider' => '7', 'two_factor_token' => $key->assert($request, tamper: true)])->assertStatus(400)->assertJsonPath('message', 'Webauthn');
        $this->login(['two_factor_provider' => '7', 'two_factor_token' => $key->assert($request)])->assertStatus(400)
            ->assertJsonPath('message', "Can't recover login challenge");
        $request = $this->arrayOf($this->login()->json('TwoFactorProviders2.7'));
        $this->login(['two_factor_provider' => '7', 'two_factor_token' => 'not json'])->assertStatus(400)->assertJsonPath('message', 'Serde');
        $request = $this->arrayOf($this->login()->json('TwoFactorProviders2.7'));
        $this->login(['two_factor_provider' => '7', 'two_factor_token' => $key->assert($request, counter: 5)])->assertStatus(200);
        $this->assertSame(5, data_get($this->stored(), '0.credential.cred.counter'));
        // A counter that does not grow means a cloned key.
        $request = $this->arrayOf($this->login()->json('TwoFactorProviders2.7'));
        $this->login(['two_factor_provider' => '7', 'two_factor_token' => $key->assert($request, counter: 5)])->assertStatus(400)->assertJsonPath('message', 'Webauthn');
        $request = $this->arrayOf($this->login()->json('TwoFactorProviders2.7'));
        $this->login(['two_factor_provider' => '7', 'two_factor_token' => $keys['fido-u2f']->assert($request)])->assertStatus(200);

        // Removing keys, one and then all.
        $token = $this->postJson('/api/two-factor/get-webauthn', ['masterPasswordHash' => 'client-hash'], $this->session)->json('userVerificationToken');
        $this->deleteJson('/api/two-factor/webauthn', ['id' => 9, 'userVerificationToken' => $token], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Webauthn entry not found');
        $this->deleteJson('/api/two-factor/webauthn', ['id' => 2, 'userVerificationToken' => $token], $this->session)
            ->assertStatus(200)->assertJsonPath('webAuthn.enabled', true)->assertJsonCount(3, 'webAuthn.keys');
        $token = $this->postJson('/api/two-factor/get-webauthn', ['masterPasswordHash' => 'client-hash'], $this->session)->json('userVerificationToken');
        $this->deleteJson('/api/two-factor/webauthn/all', ['userVerificationToken' => $token], $this->session)
            ->assertStatus(200)->assertExactJson(['webAuthn' => ['enabled' => false, 'keys' => []]]);
        $this->login()->assertStatus(200);
        $this->deleteJson('/api/two-factor/webauthn/all', ['userVerificationToken' => $token], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Webauthn data not found!');
    }

    public function test_backup_flags_learned_at_login(): void
    {
        $this->signUp('sqlite');
        $key = new SoftwareAuthenticator;
        $token = $this->postJson('/api/two-factor/get-webauthn', ['masterPasswordHash' => 'client-hash'], $this->session)->json('userVerificationToken');
        $this->postJson('/api/two-factor/webauthn', ['id' => 1, 'name' => 'Key', 'userVerificationToken' => $token,
            'deviceResponse' => $key->register($this->challenge($token))], $this->session)->assertStatus(200);

        // A key that was synced since, like a passkey.
        $key->backupEligible = true;
        $key->backupState = true;
        $request = $this->arrayOf($this->login()->json('TwoFactorProviders2.7'));
        $this->login(['two_factor_provider' => '7', 'two_factor_token' => $key->assert($request)])->assertStatus(200);
        $stored = $this->stored();
        $this->assertSame([true, true, 1], [data_get($stored, '0.credential.cred.backup_eligible'), data_get($stored, '0.credential.cred.backup_state'),
            data_get($stored, '0.credential.cred.counter')]);
    }

    public function test_old_data_is_migrated(): void
    {
        $this->signUp('sqlite');
        $bytes = static fn (string $data): array => array_map(ord(...), str_split($data));

        // A U2F key becomes a WebAuthn key, which still signs for the AppID.
        $u2f = new SoftwareAuthenticator;
        $u2f->counter = 3;
        TwoFactor::new($this->user->uuid, TwoFactor::TYPE_U2F, (string) json_encode([['id' => 1, 'name' => 'Old key', 'reg' => ['keyHandle' => $bytes($u2f->credentialId),
            'pubKey' => $bytes($u2f->publicKey()), 'attestationCert' => null, 'deviceName' => null], 'counter' => 3, 'compromised' => false, 'migrated' => null]]))->save();
        TwoFactor::migrateU2fToWebauthn();
        $this->assertSame(true, data_get(json_decode(TwoFactor::findByUserAndType($this->user->uuid, TwoFactor::TYPE_U2F)->data ?? '', true), '0.migrated'));
        $this->assertSame([1, 'Old key', true, 3, 'discouraged'], [data_get($this->stored(), '0.id'), data_get($this->stored(), '0.name'),
            data_get($this->stored(), '0.migrated'), data_get($this->stored(), '0.credential.cred.counter'), data_get($this->stored(), '0.credential.cred.registration_policy')]);
        $request = $this->arrayOf($this->login()->json('TwoFactorProviders2.7'));
        $this->login(['two_factor_provider' => '7', 'two_factor_token' => $u2f->assert($request, appid: 'http://localhost/app-id.json')])->assertStatus(200);
        // Done once only.
        TwoFactor::migrateU2fToWebauthn();
        $this->assertCount(1, $this->stored());

        // Removing the migrated key removes the U2F registration as well.
        $token = $this->postJson('/api/two-factor/get-webauthn', ['masterPasswordHash' => 'client-hash'], $this->session)->json('userVerificationToken');
        $this->deleteJson('/api/two-factor/webauthn', ['id' => 1, 'userVerificationToken' => $token], $this->session)->assertStatus(200);
        $this->assertNull(TwoFactor::findByUserAndType($this->user->uuid, TwoFactor::TYPE_U2F));

        // A key stored by webauthn-rs 0.3.
        $old = new SoftwareAuthenticator;
        $point = $old->publicKey();
        TwoFactor::new($this->user->uuid, TwoFactor::TYPE_WEBAUTHN, (string) json_encode([['id' => 2, 'name' => 'v3 key', 'migrated' => false, 'credential' => [
            'cred_id' => $bytes($old->credentialId), 'cred' => ['type_' => 'ES256', 'key' => ['EC_EC2' => ['curve' => 'SECP256R1',
                'x' => $bytes(substr($point, 1, 32)), 'y' => $bytes(substr($point, 33))]]], 'counter' => 0, 'verified' => false, 'registration_policy' => 'discouraged',
        ]]]))->save();
        TwoFactor::migrateCredentialToPasskey();
        $this->assertSame([SoftwareAuthenticator::base64($old->credentialId), SoftwareAuthenticator::base64(substr($point, 1, 32)), 'none'],
            [data_get($this->stored(), '0.credential.cred.cred_id'), data_get($this->stored(), '0.credential.cred.cred.key.EC_EC2.x'),
                data_get($this->stored(), '0.credential.cred.attestation_format')]);
        $request = $this->arrayOf($this->login()->json('TwoFactorProviders2.7'));
        $this->login(['two_factor_provider' => '7', 'two_factor_token' => $old->assert($request)])->assertStatus(200);
    }

    public function test_unsupported_domain(): void
    {
        $this->changeVaultwardenEnvironment(['DOMAIN' => 'http://127.0.0.1']);
        $this->signUp('sqlite');
        $this->postJson('/api/two-factor/get-webauthn', ['masterPasswordHash' => 'client-hash'], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Configured `DOMAIN` is not compatible with Webauthn');
    }

    /**
     * @return array<mixed>
     */
    private function challenge(mixed $token): array
    {
        return $this->arrayOf($this->postJson('/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => $token], $this->session)
            ->assertStatus(200)->json('options'));
    }

    /**
     * The stored registrations, decoded.
     *
     * @return array<mixed>
     */
    private function stored(): array
    {
        return $this->arrayOf(json_decode(TwoFactor::findByUserAndType($this->user->uuid, TwoFactor::TYPE_WEBAUTHN)->data ?? '', true));
    }

    /**
     * @return array<mixed>
     */
    private function arrayOf(mixed $value): array
    {
        $this->assertIsArray($value);

        return $value;
    }

    private function signUp(string $driver): void
    {
        $this->useDatabase($driver);
        $this->user = User::new('judy@example.com', 'Judy');
        $this->user->setPassword('client-hash', 'user-key', resetSecurityStamp: false, allowNextRoute: null);
        $this->user->save();
        $device = Device::new(Random::uuid(), $this->user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->session = ['Authorization' => 'Bearer '.LoginClaims::default($device, $this->user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];
    }

    /**
     * @param  array<string, string>  $changes
     * @return TestResponse<Response>
     */
    private function login(array $changes = []): TestResponse
    {
        return $this->call('POST', '/identity/connect/token', server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], content: http_build_query([
            'grant_type' => 'password', 'username' => 'judy@example.com', 'password' => 'client-hash', 'scope' => 'api offline_access',
            'client_id' => 'cli', 'device_identifier' => self::DEVICE, 'device_name' => 'linux', 'device_type' => '25', ...$changes,
        ]));
    }
}
