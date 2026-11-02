<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Http\Controllers\TwoFactor\AuthenticatorController;
use App\Mail\Transport;
use App\Models\AuthRequest;
use App\Models\Device;
use App\Models\TwoFactor;
use App\Models\TwoFactorIncomplete;
use App\Models\User;
use App\Support\Base32;
use App\Support\Dates;
use App\Support\Random;
use Illuminate\Http\Response;
use Illuminate\Testing\TestResponse;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\Fakes\MailTransportFake;
use Tests\TestCase;

/**
 * Two-factor login (src/api/core/two_factor, src/api/identity.rs).
 */
class TwoFactorTest extends TestCase
{
    use UsesVaultwardenDatabase;

    private const string DEVICE = '0b7f4e5c-1d2a-4b3c-8d9e-0f1a2b3c4d5e';

    private User $user;

    /**
     * @var array<string, string>
     */
    private array $session;

    private MailTransportFake $mails;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000', 'SMTP_HOST' => 'localhost', 'SMTP_FROM' => 'vault@example.com', 'LOGIN_RATELIMIT_MAX_BURST' => '100'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');
        $this->mails = new MailTransportFake;
        $this->app->instance(Transport::class, $this->mails);

        $this->user = User::new('judy@example.com', 'Judy');
        $this->user->setPassword('client-hash', 'user-key', resetSecurityStamp: false, allowNextRoute: null);
        $this->user->save();
        $device = Device::new(Random::uuid(), $this->user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->session = ['Authorization' => 'Bearer '.LoginClaims::default($device, $this->user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];
    }

    public function test_authenticator_and_remembered_devices(): void
    {
        $this->get('/api/two-factor', $this->session)->assertExactJson(['continuationToken' => null, 'data' => [], 'object' => 'list']);
        $this->postJson('/api/two-factor/get-authenticator', ['masterPasswordHash' => 'wrong'], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Invalid password');

        $setup = $this->postJson('/api/two-factor/get-authenticator', ['masterPasswordHash' => 'client-hash'], $this->session)->assertStatus(200);
        $setup->assertJsonPath('authenticator.enabled', false);
        $key = $this->string($setup->json('authenticator.key'));
        $verification = $this->string($setup->json('userVerificationToken'));
        $this->assertMatchesRegularExpression('/^[A-Z2-7]{32}$/', $key);
        $secret = Base32::decode($key);
        $this->assertNotNull($secret);

        $activate = ['key' => $key, 'userVerificationToken' => $verification];
        $this->postJson('/api/two-factor/authenticator', [...$activate, 'token' => $this->otherCode($secret)], $this->session)
            ->assertStatus(400)->assertJsonPath('message', fn (string $message): bool => str_starts_with($message, 'Invalid TOTP code! Server time: '));
        // The token is checked before the key.
        $this->postJson('/api/two-factor/authenticator', [...$activate, 'key' => 'AAAA', 'token' => '123456'], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Invalid verification token: Invalid key');
        $this->postJson('/api/two-factor/authenticator', [...$activate, 'userVerificationToken' => 'nope', 'token' => '123456'], $this->session)
            ->assertStatus(400)->assertJsonPath('message', fn (string $message): bool => str_starts_with($message, 'Failed to decode verification token: '));
        // A number works as well as a string, unless it loses a leading zero.
        $code = AuthenticatorController::totp($secret, time());
        $this->postJson('/api/two-factor/authenticator', [...$activate, 'token' => $code[0] === '0' ? $code : (int) $code], $this->session)
            ->assertStatus(200)->assertExactJson(['authenticator' => ['enabled' => true, 'key' => $key]]);
        $this->assertNotNull($this->user->refresh()->totp_recover);
        $this->get('/api/two-factor', $this->session)->assertJsonPath('data', [['enabled' => true, 'object' => 'twoFactorProvider', 'type' => 0]]);

        // Without its second factor a login gets the methods to choose from.
        $this->login()->assertStatus(400)->assertExactJson([
            'MasterPasswordPolicy' => ['Object' => 'masterPasswordPolicy'],
            'TwoFactorProviders' => ['0'],
            'TwoFactorProviders2' => ['0' => null],
            'error' => 'invalid_grant',
            'error_description' => 'Two factor required.',
        ]);
        $this->assertNotNull(TwoFactorIncomplete::findByUserAndDevice($this->user->uuid, self::DEVICE));
        $this->login(['two_factor_provider' => '1', 'two_factor_token' => '123456'])->assertStatus(400)->assertJsonPath('TwoFactorProviders', ['0']);
        $this->login(['two_factor_token' => ' '])->assertStatus(400)->assertJsonPath('error_description', 'Two factor required.');
        $this->login(['two_factor_provider' => '0', 'two_factor_token' => 'abc'])->assertStatus(400)->assertJsonPath('message', 'TOTP code is not a number');
        // The code of the activation is used up, even after its 30 seconds turned.
        $this->login(['two_factor_provider' => '0', 'two_factor_token' => $code])
            ->assertStatus(400)->assertJsonPath('message', fn (string $message): bool => str_starts_with($message, 'Invalid TOTP code!'));

        $remembered = $this->login(['twofactorprovider' => '0', 'twofactortoken' => AuthenticatorController::totp($secret, time() + 30), 'twofactorremember' => '1'])
            ->assertStatus(200);
        $token = $this->string($remembered->json('TwoFactorToken'));
        $this->assertNull(TwoFactorIncomplete::findByUserAndDevice($this->user->uuid, self::DEVICE));
        $this->assertSame($token, $this->rememberToken());

        $this->login(['two_factor_provider' => '5', 'two_factor_token' => $token])->assertStatus(200)->assertJsonMissingPath('TwoFactorToken');
        $this->login(['two_factor_provider' => '5', 'two_factor_token' => 'nope'])->assertStatus(400)->assertJsonPath('TwoFactorProviders', ['0']);
        // A wrong token drops the remembered one.
        $this->assertNull($this->rememberToken());
        $this->login(['two_factor_provider' => '5', 'two_factor_token' => $token])->assertStatus(400);

        $disable = $this->postJson('/api/two-factor/get-authenticator', ['masterPasswordHash' => 'client-hash'], $this->session)->assertJsonPath('authenticator.enabled', true);
        $this->deleteJson('/api/two-factor/authenticator', ['key' => $key, 'userVerificationToken' => $verification], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Invalid verification token: Invalid state');
        $this->deleteJson('/api/two-factor/authenticator', ['key' => $key, 'userVerificationToken' => $disable->json('userVerificationToken')], $this->session)
            ->assertStatus(200);
        $this->get('/api/two-factor', $this->session)->assertJsonPath('data', []);
        $this->login()->assertStatus(200);
    }

    public function test_recovery_code(): void
    {
        $this->enableAuthenticator();
        $code = $this->postJson('/api/two-factor/get-recover', ['masterPasswordHash' => 'client-hash'], $this->session)
            ->assertStatus(200)->assertJsonPath('object', 'twoFactorRecover')->json('code');
        $code = $this->string($code);
        $this->assertSame($this->user->refresh()->totp_recover, $code);

        $this->login(['two_factor_provider' => '8', 'two_factor_token' => 'wrong'])->assertStatus(400)
            ->assertJsonPath('message', 'Two-step token is invalid. Try again.');
        // Spaces and case do not matter.
        $this->login(['two_factor_provider' => '8', 'two_factor_token' => strtoupper(implode(' ', str_split($code, 4)))])->assertStatus(200);
        $this->assertSame(0, TwoFactor::query()->where('user_uuid', $this->user->uuid)->count());
        $this->assertNull($this->user->refresh()->totp_recover);
        $this->assertContains('Two-Step Login Recovered From 127.0.0.1', array_column($this->mails->sent, 'subject'));
        $this->login()->assertStatus(200);
    }

    public function test_unusable_and_unknown_methods(): void
    {
        // Without Yubico credentials the key cannot be checked.
        TwoFactor::new($this->user->uuid, TwoFactor::TYPE_YUBIKEY, '{"Keys":["ccccccabcdef"],"Nfc":false}')->save();
        $this->login()->assertStatus(400)->assertJsonPath('message', 'No enabled and usable two factor providers are available for this account');

        $this->enableAuthenticator();
        $this->login(['two_factor_provider' => '3', 'two_factor_token' => 'x'])->assertStatus(400)->assertJsonPath('TwoFactorProviders', ['0']);
        // A provider that is no number counts as none.
        $this->login(['two_factor_provider' => 'x', 'two_factor_token' => 'abc'])->assertStatus(400)->assertJsonPath('message', 'TOTP code is not a number');
    }

    #[Parity('config:EMAIL_ATTEMPTS_LIMIT')]
    public function test_email_codes(): void
    {
        $setup = $this->postJson('/api/two-factor/get-email', ['masterPasswordHash' => 'client-hash'], $this->session)
            ->assertStatus(200)->assertJsonPath('email', ['email' => null, 'enabled' => false]);
        $verification = $setup->json('userVerificationToken');

        $this->postJson('/api/two-factor/send-email', ['email' => 'second@example.com', 'userVerificationToken' => $verification], $this->session)
            ->assertStatus(200)->assertExactJson([]);
        $code = $this->mailedCode('second@example.com');
        $this->putJson('/api/two-factor/email', ['email' => 'second@example.com', 'token' => 'nope', 'userVerificationToken' => $verification], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Token is invalid');
        $this->putJson('/api/two-factor/email', ['email' => 'second@example.com', 'token' => $code, 'userVerificationToken' => $verification], $this->session)
            ->assertStatus(200);
        $this->postJson('/api/two-factor/get-email', ['masterPasswordHash' => 'client-hash'], $this->session)
            ->assertJsonPath('email', ['email' => 'second@example.com', 'enabled' => true]);

        $this->login()->assertStatus(400)->assertJsonPath('TwoFactorProviders2', ['1' => ['Email' => 'se****@example.com']]);
        $this->postJson('/api/two-factor/send-email-login', ['email' => 'judy@example.com', 'masterPasswordHash' => 'wrong'])
            ->assertStatus(400)->assertJsonPath('message', 'Username or password is incorrect. Try again');
        $this->postJson('/api/two-factor/send-email-login', ['email' => 'judy@example.com'])
            ->assertStatus(400)->assertJsonPath('message', 'No password hash has been submitted.');
        // A pending login names the user.
        $this->postJson('/api/two-factor/send-email-login', ['deviceIdentifier' => self::DEVICE])->assertStatus(200);
        $code = $this->mailedCode('second@example.com');

        $this->login(['two_factor_provider' => '1', 'two_factor_token' => 'nope'])->assertStatus(400)
            ->assertJsonPath('message', 'Token is invalid! IP: 127.0.0.1');
        $this->login(['two_factor_provider' => '1', 'two_factor_token' => $code])->assertStatus(200);
        $this->login(['two_factor_provider' => '1', 'two_factor_token' => $code])->assertStatus(400)
            ->assertJsonPath('message', 'No token available! IP: 127.0.0.1');

        $this->postJson('/api/two-factor/send-email-login', ['email' => 'judy@example.com', 'masterPasswordHash' => 'client-hash'])->assertStatus(200);
        $this->mailedCode('second@example.com');
        // After the limit of wrong codes the code is gone.
        $this->changeVaultwardenEnvironment(['EMAIL_ATTEMPTS_LIMIT' => '2']);
        $this->login(['two_factor_provider' => '1', 'two_factor_token' => 'one'])->assertStatus(400);
        $this->login(['two_factor_provider' => '1', 'two_factor_token' => 'two'])->assertStatus(400);
        $this->assertStringContainsString('"last_token":null', TwoFactor::findByUserAndType($this->user->uuid, TwoFactor::TYPE_EMAIL)->data ?? '');

        $disable = $this->postJson('/api/two-factor/get-email', ['masterPasswordHash' => 'client-hash'], $this->session)->json('userVerificationToken');
        $this->deleteJson('/api/two-factor/email', ['userVerificationToken' => $verification], $this->session)
            ->assertStatus(400)->assertJsonPath('message', 'Invalid verification token: Invalid state');
        $this->deleteJson('/api/two-factor/email', ['userVerificationToken' => $disable], $this->session)->assertStatus(200);
        $this->login()->assertStatus(200);
    }

    #[Parity('config:EMAIL_TOKEN_SIZE')]
    #[Parity('config:EMAIL_EXPIRATION_TIME')]
    public function test_email_code_size_and_expiry(): void
    {
        $this->changeVaultwardenEnvironment(['EMAIL_TOKEN_SIZE' => '8', 'EMAIL_EXPIRATION_TIME' => '60']);
        TwoFactor::new($this->user->uuid, TwoFactor::TYPE_EMAIL, '{"email":"judy@example.com","last_token":null,"token_sent":0,"attempts":0}')->save();

        $this->postJson('/api/two-factor/send-email-login', ['email' => 'judy@example.com', 'masterPasswordHash' => 'client-hash'])->assertStatus(200);
        $code = $this->mailedCode('judy@example.com', 8);
        $method = TwoFactor::findByUserAndType($this->user->uuid, TwoFactor::TYPE_EMAIL);
        $this->assertNotNull($method);
        $method->data = (string) preg_replace('/"token_sent":\d+/', '"token_sent":'.(time() - 61), $method->data);
        $method->save();

        $this->login(['two_factor_provider' => '1', 'two_factor_token' => $code])->assertStatus(400)->assertJsonPath('message', 'Token has expired');
        // Used up all the same.
        $this->login(['two_factor_provider' => '1', 'two_factor_token' => $code])->assertStatus(400)->assertJsonPath('message', 'No token available! IP: 127.0.0.1');
    }

    #[Parity('config:AUTHENTICATOR_DISABLE_TIME_DRIFT')]
    public function test_time_drift(): void
    {
        $secret = $this->storeAuthenticator();
        $this->changeVaultwardenEnvironment(['AUTHENTICATOR_DISABLE_TIME_DRIFT' => 'true']);
        self::awayFromStepBoundary();

        $this->login(['two_factor_provider' => '0', 'two_factor_token' => AuthenticatorController::totp($secret, time() + 30)])->assertStatus(400)
            ->assertJsonPath('message', fn (string $message): bool => str_starts_with($message, 'Invalid TOTP code!'));
        $this->login(['two_factor_provider' => '0', 'two_factor_token' => AuthenticatorController::totp($secret, time())])->assertStatus(200);
    }

    #[Parity('config:DISABLE_2FA_REMEMBER')]
    public function test_remembering_disabled(): void
    {
        $secret = $this->storeAuthenticator();
        $this->changeVaultwardenEnvironment(['DISABLE_2FA_REMEMBER' => 'true']);
        self::awayFromStepBoundary();

        $this->login(['two_factor_provider' => '0', 'two_factor_token' => AuthenticatorController::totp($secret, time()), 'two_factor_remember' => '1'])
            ->assertStatus(200)->assertJsonMissingPath('TwoFactorToken');
        // A token from before no longer counts.
        $device = Device::findByUuidAndUser(self::DEVICE, $this->user->uuid);
        $this->assertNotNull($device);
        $token = $device->refreshTwofactorRemember();
        $device->save();
        $this->login(['two_factor_provider' => '5', 'two_factor_token' => $token])->assertStatus(400)->assertJsonPath('error_description', 'Two factor required.');
        $this->assertNull($this->rememberToken());
    }

    /**
     * Vaultwarden acb574b7: a login request stands in for the password only
     * when it belongs to the user and is approved, unused and recent.
     */
    public function test_an_email_code_for_a_login_request(): void
    {
        TwoFactor::new($this->user->uuid, TwoFactor::TYPE_EMAIL, '{"email":"judy@example.com","last_token":null,"token_sent":0,"attempts":0}')->save();
        $other = User::new('other@example.com');
        $other->save();
        $request = static function (User $user, ?bool $approved, string $created = 'now', bool $used = false): string {
            $request = AuthRequest::new($user->uuid, self::DEVICE, 10, '127.0.0.1', 'access-code', 'public-key');
            $request->approved = $approved;
            $request->creation_date = Dates::now()->modify($created);
            $request->authentication_date = $used ? Dates::now() : null;
            $request->save();

            return $request->uuid;
        };
        $send = fn (string $id, array $changes = [], string $deviceType = '10') => $this->postJson('/api/two-factor/send-email-login',
            ['email' => 'judy@example.com', 'authRequestId' => $id, 'authRequestAccessCode' => 'access-code', ...$changes], ['Device-Type' => $deviceType]);

        $approved = $request($this->user, true);
        $send($approved, ['authRequestAccessCode' => null])->assertStatus(400)->assertJsonPath('message', 'no auth request access code');
        self::refused($send($request($this->user, null)));
        self::refused($send($request($this->user, false)));
        self::refused($send($request($this->user, true, '-6 minutes')));
        self::refused($send($request($this->user, true, used: true)));
        self::refused($send($request($other, true)));
        self::refused($send($approved, ['authRequestAccessCode' => 'wrong']));
        self::refused($send($approved, deviceType: '9'));
        $this->assertSame([], $this->mails->sent);

        $send($approved)->assertStatus(200);
        $this->assertCount(1, $this->mails->sent);
    }

    #[Parity('config:TWO_FACTOR_REMEMBER_DAYS')]
    public function test_remembering_for_the_configured_days(): void
    {
        $secret = $this->storeAuthenticator();
        self::awayFromStepBoundary();
        $lifetime = function (string $token): int {
            $claims = json_decode((string) base64_decode(strtr(explode('.', $token)[1], '-_', '+/')), true);
            $this->assertIsArray($claims);
            $this->assertIsInt($claims['exp']);
            $this->assertIsInt($claims['nbf']);

            return $claims['exp'] - $claims['nbf'];
        };

        $token = $this->string($this->login(['two_factor_provider' => '0', 'two_factor_token' => AuthenticatorController::totp($secret, time()), 'two_factor_remember' => '1'])
            ->assertStatus(200)->json('TwoFactorToken'));
        $this->assertSame(30 * 86_400, $lifetime($token));

        // Vaultwarden 0dbc92f2: TWO_FACTOR_REMEMBER_DAYS.
        $this->changeVaultwardenEnvironment(['TWO_FACTOR_REMEMBER_DAYS' => '7']);
        $token = $this->string($this->login(['two_factor_provider' => '5', 'two_factor_token' => $token, 'two_factor_remember' => '1'])
            ->assertStatus(200)->json('TwoFactorToken'));
        $this->assertSame(7 * 86_400, $lifetime($token));
    }

    public function test_protected_actions(): void
    {
        $this->postJson('/api/accounts/request-otp', [], $this->session)->assertStatus(200);
        $code = $this->mailedCode('judy@example.com');
        $this->postJson('/api/accounts/request-otp', [], $this->session)->assertStatus(400)
            ->assertJsonPath('message', fn (string $message): bool => (bool) preg_match('/^Please wait \d+ seconds before requesting another code\.$/', $message));

        $this->postJson('/api/accounts/verify-otp', ['otp' => 'nope'], $this->session)->assertStatus(400)->assertJsonPath('message', 'Token is invalid');
        $this->postJson('/api/accounts/verify-otp', ['OTP' => $code], $this->session)->assertStatus(200);
        // A code works once.
        $this->postJson('/api/accounts/verify-otp', ['OTP' => $code], $this->session)->assertStatus(400);
    }

    private function enableAuthenticator(): void
    {
        $setup = $this->postJson('/api/two-factor/get-authenticator', ['masterPasswordHash' => 'client-hash'], $this->session);
        $key = $this->string($setup->json('authenticator.key'));
        $this->postJson('/api/two-factor/authenticator', ['key' => $key, 'userVerificationToken' => $setup->json('userVerificationToken'),
            'token' => AuthenticatorController::totp(Base32::decode($key) ?? '', time())], $this->session)->assertStatus(200);
    }

    /**
     * An authenticator whose codes were never used; returns its secret.
     */
    /**
     * @param  TestResponse<Response>  $response
     */
    private static function refused(TestResponse $response): void
    {
        $response->assertStatus(400)->assertJsonPath('message', "AuthRequest doesn't exist");
    }

    private function storeAuthenticator(): string
    {
        $key = Random::base32(20);
        TwoFactor::new($this->user->uuid, TwoFactor::TYPE_AUTHENTICATOR, $key)->save();

        return Base32::decode($key) ?? '';
    }

    /**
     * Leaves time for a request before the next 30-second step begins.
     */
    private static function awayFromStepBoundary(): void
    {
        $left = 30 - time() % 30;
        if ($left < 3) {
            sleep($left);
        }
    }

    /**
     * A code that belongs to no step near now.
     */
    private function otherCode(string $secret): string
    {
        // The server's window may move on by a step before it checks.
        $near = array_map(static fn (int $step): string => AuthenticatorController::totp($secret, time() + $step * 30), [-1, 0, 1, 2]);
        for ($code = 0; in_array(sprintf('%06d', $code), $near, true); $code++);

        return sprintf('%06d', $code);
    }

    private function mailedCode(string $to, int $length = 6): string
    {
        if (preg_match('/\b(\d{'.$length.'})\b/', $this->mails->last($to)['text'], $match) !== 1) {
            $this->fail("No code in the mail to {$to}.");
        }

        return $match[1];
    }

    private function rememberToken(): ?string
    {
        return Device::findByUuidAndUser(self::DEVICE, $this->user->uuid)?->twofactor_remember;
    }

    private function string(mixed $value): string
    {
        $this->assertIsString($value);

        return $value;
    }

    /**
     * @param  array<string, string>  $changes
     * @return TestResponse<Response>
     */
    private function login(array $changes = []): TestResponse
    {
        return $this->call('POST', '/identity/connect/token', server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], content: http_build_query([
            'grant_type' => 'password',
            'username' => 'judy@example.com',
            'password' => 'client-hash',
            'scope' => 'api offline_access',
            'client_id' => 'cli',
            'device_identifier' => self::DEVICE,
            'device_name' => 'linux',
            'device_type' => '25',
            ...$changes,
        ]));
    }
}
