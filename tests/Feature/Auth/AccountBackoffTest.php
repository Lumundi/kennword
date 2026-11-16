<?php

namespace Tests\Feature\Auth;

use App\Auth\AccountBackoff;
use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Http\ApiError;
use App\Http\Controllers\TwoFactor\AuthenticatorController;
use App\Http\Data\PasswordOrOtpData;
use App\Mail\Transport;
use App\Models\Device;
use App\Models\TwoFactor;
use App\Models\User;
use App\Support\Base32;
use App\Support\Random;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Http\Response;
use Illuminate\Testing\TestResponse;
use RuntimeException;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\Fakes\MailTransportFake;
use Tests\TestCase;

/**
 * Kennword's backoff per account: failed checks of the master password and
 * of typed codes, from any address, hold the account back for a while.
 */
class AccountBackoffTest extends TestCase
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
        // The limit per address out of the way, as for guesses from many addresses.
        return ['PASSWORD_ITERATIONS' => '100000', 'LOGIN_RATELIMIT_MAX_BURST' => '1000',
            'SMTP_HOST' => 'localhost', 'SMTP_FROM' => 'vault@example.com'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');
        $this->app->instance(Transport::class, new MailTransportFake);

        $this->user = $this->account('backoff@example.com');
        $device = Device::new(Random::uuid(), $this->user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->session = ['Authorization' => 'Bearer '.LoginClaims::default($device, $this->user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];
    }

    public function test_wrong_passwords_hold_the_account_back_for_a_while(): void
    {
        for ($i = 0; $i < AccountBackoff::MAX_FAILURES; $i++) {
            $this->login(['password' => 'wrong'])->assertStatus(400)->assertJsonPath('message', 'Username or password is incorrect. Try again');
        }

        // The right password as well, also where it is the proof for a change.
        $this->login()->assertStatus(429)->assertJsonPath('message', AccountBackoff::MESSAGE);
        $this->postJson('/api/accounts/verify-password', ['masterPasswordHash' => 'client-hash'], $this->session)->assertStatus(429);
        $this->postJson('/api/accounts/api-key', ['masterPasswordHash' => 'client-hash'], $this->session)->assertStatus(429);
        $this->postJson('/api/two-factor/send-email-login', ['email' => 'backoff@example.com', 'masterPasswordHash' => 'client-hash'])->assertStatus(429);

        // Other accounts log in.
        $this->account('other@example.com');
        $this->login(['username' => 'other@example.com'])->assertStatus(200);

        // Once the oldest failure is out of the window, one more attempt is taken.
        $this->age(1);
        $this->login()->assertStatus(200);
        $this->login(['password' => 'wrong'])->assertStatus(400);
        $this->login()->assertStatus(429);

        // Nothing holds an account for good.
        $this->age(AccountBackoff::MAX_FAILURES);
        $this->login()->assertStatus(200);
    }

    public function test_successful_attempts_leave_the_failures_counted(): void
    {
        for ($i = 0; $i < AccountBackoff::MAX_FAILURES - 1; $i++) {
            $this->login(['password' => 'wrong'])->assertStatus(400);
        }
        // Successes do not count, and they take back no failure either.
        for ($i = 0; $i < 3; $i++) {
            $this->login()->assertStatus(200);
        }
        $this->login(['password' => 'wrong'])->assertStatus(400);

        $this->login()->assertStatus(429);
    }

    public function test_addresses_without_an_account_answer_alike(): void
    {
        for ($i = 0; $i < AccountBackoff::MAX_FAILURES; $i++) {
            $this->login(['username' => $i % 2 === 0 ? 'nobody@example.com' : ' Nobody@Example.com'])->assertStatus(400)
                ->assertJsonPath('message', 'Username or password is incorrect. Try again');
        }

        $this->login(['username' => 'nobody@example.com'])->assertStatus(429)->assertJsonPath('message', AccountBackoff::MESSAGE);
        $this->postJson('/api/two-factor/send-email-login', ['email' => 'nobody@example.com', 'masterPasswordHash' => 'client-hash'])->assertStatus(429);
        $this->login()->assertStatus(200);
    }

    public function test_typed_two_factor_codes_count(): void
    {
        $key = Random::base32(20);
        TwoFactor::new($this->user->uuid, TwoFactor::TYPE_AUTHENTICATOR, $key)->save();
        $this->user->totp_recover = 'recoverycode';
        $this->user->save();
        $secret = Base32::decode($key) ?? '';
        $wrong = $this->otherCode($secret);

        // With the right password, which takes back its own attempt.
        for ($i = 0; $i < AccountBackoff::MAX_FAILURES / 2; $i++) {
            $this->login(['two_factor_provider' => '0', 'two_factor_token' => $wrong])->assertStatus(400);
            $this->login(['two_factor_provider' => '8', 'two_factor_token' => 'wrong'])->assertStatus(400)
                ->assertJsonPath('message', 'Two-step token is invalid. Try again.');
        }

        $this->login(['two_factor_provider' => '0', 'two_factor_token' => AuthenticatorController::totp($secret, time())])->assertStatus(429);
        $this->login(['two_factor_provider' => '8', 'two_factor_token' => 'recoverycode'])->assertStatus(429);
    }

    public function test_master_password_and_code_proofs_count(): void
    {
        TwoFactor::new($this->user->uuid, TwoFactor::TYPE_PROTECTED_ACTIONS, PasswordOrOtpData::encodeProtectedActionData('12345678', time(), 0))->save();
        $failures = [
            ['/api/accounts/verify-password', ['masterPasswordHash' => 'wrong'], 'Invalid password'],
            ['/api/accounts/api-key', ['masterPasswordHash' => 'wrong'], 'Invalid password'],
            ['/api/accounts/security-stamp', ['masterPasswordHash' => 'wrong'], 'Invalid password'],
            ['/api/accounts/password', ['masterPasswordHash' => 'wrong', 'newMasterPasswordHash' => 'new', 'key' => '2.new'], 'Invalid password'],
            ['/api/accounts/email-token', ['masterPasswordHash' => 'wrong', 'newEmail' => 'new@example.com'], 'Invalid password'],
            ['/api/two-factor/get-recover', ['masterPasswordHash' => 'wrong'], 'Invalid password'],
            ['/api/two-factor/get-authenticator', ['otp' => '00000000'], 'Token is invalid'],
            ['/api/accounts/verify-otp', ['otp' => '00000000'], 'Token is invalid'],
            ['/api/two-factor/send-email-login', ['email' => 'backoff@example.com', 'masterPasswordHash' => 'wrong'], 'Username or password is incorrect. Try again'],
        ];
        foreach ($failures as [$route, $body, $message]) {
            $this->postJson($route, $body, $this->session)->assertStatus(400)->assertJsonPath('message', $message);
        }
        $this->login(['password' => 'wrong'])->assertStatus(400);
        $this->assertSame(AccountBackoff::MAX_FAILURES, count($failures) + 1);

        $this->postJson('/api/accounts/verify-password', ['masterPasswordHash' => 'client-hash'], $this->session)->assertStatus(429)
            ->assertJsonPath('message', AccountBackoff::MESSAGE);
        $this->login()->assertStatus(429);
    }

    /**
     * A check counts while it runs, so that parallel guesses do not get past
     * the limit; one that throws counts like one that fails.
     */
    public function test_checks_count_while_they_run(): void
    {
        $backoff = $this->app->make(AccountBackoff::class);
        $refused = null;
        $nested = function (int $depth) use (&$nested, &$refused, $backoff): bool {
            if ($depth === AccountBackoff::MAX_FAILURES) {
                try {
                    $backoff->attempt('account', static fn (): bool => true);
                } catch (ApiError $error) {
                    $refused = $error->status;
                }

                return true;
            }

            return $backoff->attempt('account', static fn (): bool => $nested($depth + 1));
        };
        $this->assertTrue($nested(0));
        $this->assertSame(429, $refused);

        // All of them succeeded, so nothing is left counted.
        for ($i = 0; $i < AccountBackoff::MAX_FAILURES - 1; $i++) {
            $this->assertFalse($backoff->attempt('account', static fn (): bool => false));
        }
        try {
            $backoff->attempt('account', static fn (): bool => throw new RuntimeException('Yubico is down'));
            $this->fail('The check should throw.');
        } catch (RuntimeException $error) {
            $this->assertSame('Yubico is down', $error->getMessage());
        }
        $this->expectExceptionObject(ApiError::message(AccountBackoff::MESSAGE, 429));
        $backoff->attempt('account', static fn (): bool => true);
    }

    /**
     * Servers keep the attempts in Laravel's file cache, shared by all PHP workers.
     */
    public function test_the_file_cache_keeps_the_attempts(): void
    {
        $directory = "{$this->dataFolder}/cache";
        $workers = [new AccountBackoff(new CacheRepository(new FileStore(new Filesystem, $directory))),
            new AccountBackoff(new CacheRepository(new FileStore(new Filesystem, $directory)))];

        $this->assertTrue($workers[0]->attempt('account', static fn (): bool => true));
        for ($i = 0; $i < AccountBackoff::MAX_FAILURES; $i++) {
            $this->assertFalse($workers[$i % 2]->attempt('account', static fn (): bool => false));
        }

        $this->expectExceptionObject(ApiError::message(AccountBackoff::MESSAGE, 429));
        $workers[1]->attempt('account', static fn (): bool => true);
    }

    private function account(string $email): User
    {
        $user = User::new($email);
        $user->setPassword('client-hash', 'user-key', resetSecurityStamp: false, allowNextRoute: null);
        $user->save();

        return $user;
    }

    /**
     * Moves the oldest failures of the account out of the window.
     */
    private function age(int $count): void
    {
        $cache = $this->app->make(Repository::class);
        $key = "vaultwarden:backoff:user:{$this->user->uuid}";
        $stored = $cache->get($key);
        $this->assertIsArray($stored);
        $attempts = array_filter($stored, is_float(...));
        $this->assertCount(count($stored), $attempts);
        asort($attempts);
        foreach (array_slice(array_keys($attempts), 0, $count) as $id) {
            $attempts[$id] -= AccountBackoff::WINDOW;
        }
        $cache->put($key, $attempts, AccountBackoff::WINDOW);
    }

    /**
     * A code that belongs to no step near now.
     */
    private function otherCode(string $secret): string
    {
        $near = array_map(static fn (int $step): string => AuthenticatorController::totp($secret, time() + $step * 30), [-1, 0, 1, 2]);
        for ($code = 0; in_array(sprintf('%06d', $code), $near, true); $code++);

        return sprintf('%06d', $code);
    }

    /**
     * @param  array<string, string>  $changes
     * @return TestResponse<Response>
     */
    private function login(array $changes = []): TestResponse
    {
        return $this->call('POST', '/identity/connect/token', server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], content: http_build_query([
            'grant_type' => 'password',
            'username' => 'backoff@example.com',
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
