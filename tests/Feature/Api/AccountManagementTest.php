<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\AuthRequest;
use App\Models\Device;
use App\Models\Folder;
use App\Models\User;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * Account management, devices and logins with a device (src/api/core/accounts.rs).
 */
class AccountManagementTest extends TestCase
{
    use UsesVaultwardenDatabase;

    private const string DEVICE = '0b7f4e5c-1d2a-4b3c-8d9e-0f1a2b3c4d5e';

    private const string NEW_DEVICE = '0d8f2c1e-3b4a-4c5d-9e6f-7a8b9c0d1e2f';

    private User $user;

    /**
     * @var array<string, string>
     */
    private array $session;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000', 'EXPERIMENTAL_CLIENT_FEATURE_FLAGS' => 'ssh-agent-v2, nope', 'CLIENT_SUPPRESS_ONBOARDING' => 'true'];
    }

    #[Parity('config:EXPERIMENTAL_CLIENT_FEATURE_FLAGS')]
    #[Parity('config:CLIENT_SUPPRESS_ONBOARDING')]
    public function test_config_names_us(): void
    {
        $this->signUp('sqlite');
        $config = $this->get('/api/config')->assertStatus(200);
        $config->assertJsonPath('server', ['name' => 'Kennword', 'url' => 'https://github.com/Lumundi/kennword'])
            ->assertJsonPath('settings.suppressOnboardingInterstitials', true)
            ->assertJsonPath('environment.api', 'http://localhost/api')
            ->assertJsonPath('featureStates', ['pm-19148-innovation-archive' => true, 'ssh-agent-v2' => true])
            ->assertJsonPath('version', '2026.6.0');
        $this->assertSame(['communication', 'environment', 'featureStates', 'gitHash', 'object', 'push', 'server', 'settings', 'version'],
            array_keys($this->arrayOf($config->json())));
    }

    #[Parity('config:FILL_ASSIST_RULES_URL')]
    public function test_config_names_the_fill_assist_rules(): void
    {
        $this->signUp('sqlite');
        $this->get('/api/config')->assertJsonPath('environment.fillAssistRules', 'https://fillassist.bitwarden.com');

        $this->changeVaultwardenEnvironment(['FILL_ASSIST_RULES_URL' => 'https://rules.example/feeds']);
        $this->get('/api/config')->assertJsonPath('environment.fillAssistRules', 'https://rules.example/feeds')
            ->assertJsonPath('environment', fn (array $environment): bool => array_keys($environment)
                === ['api', 'cloudRegion', 'fillAssistRules', 'identity', 'notifications', 'sso', 'vault']);
    }

    #[DataProvider('drivers')]
    public function test_login_with_a_device(string $driver): void
    {
        $this->signUp($driver);
        $this->login(self::NEW_DEVICE, '10')->assertStatus(200);
        $asking = ['HTTP_DEVICE_TYPE' => '10'];
        $id = $this->postJson('/api/auth-requests', ['accessCode' => 'code', 'deviceIdentifier' => self::NEW_DEVICE, 'email' => 'judy@example.com',
            'publicKey' => 'device-key'], $asking)->assertStatus(200)
            ->assertJsonPath('requestDeviceType', 'Firefox')->assertJsonPath('requestApproved', false)->assertJsonPath('origin', 'http://localhost')
            ->json('id');
        $this->assertIsString($id);

        $this->get('/api/devices', $this->session)->assertJsonPath('data.1.devicePendingAuthRequest.id', $id);
        $this->get('/api/auth-requests/pending', $this->session)->assertJsonCount(1, 'data')->assertJsonPath('data.0.requestApproved', null);
        $this->putJson("/api/auth-requests/{$id}", ['deviceIdentifier' => self::DEVICE, 'key' => '4.key', 'requestApproved' => true], $this->session)
            ->assertStatus(200)->assertJsonPath('requestApproved', true)->assertJsonPath('key', '4.key');
        $this->get("/api/auth-requests/{$id}/response?code=code", $asking)->assertStatus(200)->assertJsonPath('key', '4.key');
        $this->get("/api/auth-requests/{$id}/response?code=code", ['HTTP_DEVICE_TYPE' => '9'])->assertStatus(400);

        $this->login(self::NEW_DEVICE, '10', ['password' => 'code', 'authrequest' => $id])->assertStatus(200);
        $this->assertNotNull(AuthRequest::findByUuid($id)?->authentication_date);
        $this->login(self::NEW_DEVICE, '10', ['password' => 'code', 'authrequest' => $id])->assertStatus(400)
            ->assertJsonPath('message', 'Username or access code is incorrect. Try again');

        // Expired after five minutes.
        $late = $this->postJson('/api/auth-requests', ['accessCode' => 'late', 'deviceIdentifier' => self::NEW_DEVICE, 'email' => 'judy@example.com',
            'publicKey' => 'device-key'], $asking)->json('id');
        $this->assertIsString($late);
        $this->putJson("/api/auth-requests/{$late}", ['deviceIdentifier' => self::DEVICE, 'key' => '4.key', 'requestApproved' => true], $this->session)->assertStatus(200);
        AuthRequest::query()->where('uuid', $late)->update(['creation_date' => '2020-01-01 00:00:00.000000']);
        $this->login(self::NEW_DEVICE, '10', ['password' => 'late', 'authrequest' => $late])->assertStatus(400);
    }

    #[DataProvider('drivers')]
    public function test_key_rotation_and_email_change(string $driver): void
    {
        $this->signUp($driver);
        $folder = $this->postJson('/api/folders', ['name' => '2.folder'], $this->session)->json('id');
        $this->assertIsString($folder);

        $rotation = [
            'accountUnlockData' => ['emergencyAccessUnlockData' => [], 'organizationAccountRecoveryUnlockData' => [],
                'masterPasswordUnlockData' => ['kdfType' => 0, 'kdfIterations' => 600000, 'kdfParallelism' => null, 'kdfMemory' => null,
                    'email' => 'judy@example.com', 'masterKeyAuthenticationHash' => 'rotated-hash', 'masterKeyEncryptedUserKey' => '2.rotated-key']],
            'accountKeys' => ['userKeyEncryptedAccountPrivateKey' => '2.private', 'accountPublicKey' => 'public-key'],
            'accountData' => ['ciphers' => [], 'folders' => [['id' => $folder, 'name' => '2.rotated']], 'sends' => []],
            'oldMasterKeyAuthenticationHash' => 'client-hash',
        ];
        $this->postJson('/api/accounts/key-management/user-key-id', ['userKeyId' => 'old-key-id'], $this->session)->assertStatus(200);
        $this->postJson('/api/accounts/key-management/rotate-user-account-keys', [...$rotation, 'accountData' => ['ciphers' => [], 'folders' => [], 'sends' => []]],
            $this->session)->assertStatus(400)->assertJsonPath('message', 'All existing folders must be included in the rotation');
        // Like Bitwarden's, a rotation that names the id of the new user key keeps it (Vaultwarden 1.37.5 keeps the old one).
        $this->postJson('/api/accounts/key-management/rotate-user-account-keys', [...$rotation, 'newUserKeyId' => 'rotated-key-id'], $this->session)->assertStatus(200);
        $this->assertSame('2.rotated', Folder::query()->where('uuid', $folder)->value('name'));
        $user = User::findByUuid($this->user->uuid);
        $this->assertSame(['2.rotated-key', '2.private', 'rotated-key-id'], [$user?->akey, $user?->private_key, $user?->key_id]);
        $this->assertTrue($user?->checkValidPassword('rotated-hash'));

        // Without it, the old id goes all the same: the clients record the new one, and their items, encrypted by it, are taken.
        $this->signUp($driver, fresh: false);
        $this->postJson('/api/accounts/key-management/rotate-user-account-keys', [...$rotation, 'oldMasterKeyAuthenticationHash' => 'rotated-hash'], $this->session)
            ->assertStatus(200);
        $this->assertNull(User::findByUuid($this->user->uuid)?->key_id);
        $this->signUp($driver, fresh: false);
        $this->get('/api/sync', $this->session)->assertJsonPath('userDecryption.userKeyId', null);
        $this->postJson('/api/accounts/key-management/user-key-id', ['userKeyId' => 'new-key-id'], $this->session)->assertStatus(200);
        $this->postJson('/api/ciphers', ['type' => 2, 'name' => '2.note', 'secureNote' => ['type' => 0], 'encryptedFor' => $this->user->uuid,
            'encryptedByKeyId' => 'new-key-id'], $this->session)->assertStatus(200);

        // Without mail the code is not checked and the address is not verified.
        $this->postJson('/api/accounts/email-token', ['masterPasswordHash' => 'rotated-hash', 'newEmail' => 'new@example.com'], $this->session)->assertStatus(200);
        $this->postJson('/api/accounts/email', ['masterPasswordHash' => 'rotated-hash', 'newEmail' => 'new@example.com', 'key' => '2.new',
            'newMasterPasswordHash' => 'new-hash', 'token' => 'anything'], $this->session)->assertStatus(200);
        $user = User::findByUuid($this->user->uuid);
        $this->assertSame(['new@example.com', null, null], [$user?->email, $user?->email_new, $user?->verified_at]);
    }

    #[Parity('config:EMAIL_CHANGE_ALLOWED')]
    #[Parity('config:PASSWORD_HINTS_ALLOWED')]
    #[Parity('config:SHOW_PASSWORD_HINT')]
    public function test_email_change_and_hint_settings(): void
    {
        $this->signUp('sqlite');
        $this->user->password_hint = 'the usual one';
        $this->user->save();
        $hint = fn (string $email): TestResponse => $this->postJson('/api/accounts/password-hint', ['email' => $email])->assertStatus(400);

        // Without mail, hints are only given when they may be shown.
        $hint('judy@example.com')->assertJsonPath('message', 'This server is not configured to provide password hints.');
        $this->changeVaultwardenEnvironment(['SHOW_PASSWORD_HINT' => 'true']);
        // Vaultwarden 6ed6921c: the hint is shown, but not logged.
        $log = Log::spy();
        $hint('judy@example.com')->assertJsonPath('message', 'Your password hint is: the usual one');
        $log->shouldNotHaveReceived('error');
        $hint('nobody@example.com')->assertJsonPath('message', 'Sorry, you have no password hint...');
        $log->shouldHaveReceived('error')->with('Sorry, you have no password hint...');
        $this->changeVaultwardenEnvironment(['PASSWORD_HINTS_ALLOWED' => 'false']);
        $hint('judy@example.com')->assertJsonPath('message', 'This server is not configured to provide password hints.');
        $this->postJson('/api/accounts/password', ['masterPasswordHash' => 'client-hash', 'newMasterPasswordHash' => 'new-hash', 'key' => 'new-key',
            'masterPasswordHint' => 'a new one'], $this->session)->assertStatus(400)
            ->assertJsonPath('message', 'Password hints have been disabled by the administrator. Remove the hint and try again.');

        $this->changeVaultwardenEnvironment(['EMAIL_CHANGE_ALLOWED' => 'false']);
        $this->postJson('/api/accounts/email-token', ['masterPasswordHash' => 'client-hash', 'newEmail' => 'new@example.com'], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Email change is not allowed.');
        $this->postJson('/api/accounts/email', ['masterPasswordHash' => 'client-hash', 'newEmail' => 'new@example.com', 'key' => '2.new',
            'newMasterPasswordHash' => 'new-hash', 'token' => '123456'], $this->session)->assertStatus(400)->assertJsonPath('message', 'Email change is not allowed.');
    }

    public function test_known_device(): void
    {
        $this->signUp('sqlite');
        $email = rtrim(strtr(base64_encode('judy@example.com'), '+/', '-_'), '=');
        $this->get('/api/devices/knowndevice', ['X-Request-Email' => $email, 'X-Device-Identifier' => self::DEVICE])->assertStatus(200)->assertContent('true');
        $this->get('/api/devices/knowndevice', ['X-Request-Email' => "{$email}=", 'X-Device-Identifier' => 'other'])->assertStatus(200)->assertContent('false');
        $this->get('/api/devices/knowndevice', ['X-Request-Email' => 'a+b', 'X-Device-Identifier' => self::DEVICE])->assertStatus(400);
    }

    /**
     * @return array<mixed>
     */
    private function arrayOf(mixed $value): array
    {
        $this->assertIsArray($value);

        return $value;
    }

    private function signUp(string $driver, bool $fresh = true): void
    {
        if ($fresh) {
            $this->useDatabase($driver);
            $this->user = User::new('judy@example.com', 'Judy');
            $this->user->setPassword('client-hash', 'user-key', resetSecurityStamp: false, allowNextRoute: null);
            $this->user->public_key = 'public-key';
            $this->user->save();
        }
        $user = User::findByUuid($this->user->uuid) ?? $this->user;
        $device = Device::findByUuidAndUser(self::DEVICE, $user->uuid) ?? Device::new(self::DEVICE, $user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->session = ['Authorization' => 'Bearer '.LoginClaims::default($device, $user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];
    }

    /**
     * @param  array<string, string>  $changes
     * @return TestResponse<Response>
     */
    private function login(string $device, string $type, array $changes = []): TestResponse
    {
        return $this->call('POST', '/identity/connect/token', server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], content: http_build_query([
            'grant_type' => 'password', 'username' => 'judy@example.com', 'password' => 'client-hash', 'scope' => 'api offline_access',
            'client_id' => 'web', 'device_identifier' => $device, 'device_name' => 'firefox', 'device_type' => $type, ...$changes,
        ]));
    }
}
