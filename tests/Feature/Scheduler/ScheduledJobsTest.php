<?php

namespace Tests\Feature\Scheduler;

use App\Config\Config;
use App\Mail\Transport;
use App\Models\AuthRequest;
use App\Models\Casts\NaiveDateTime;
use App\Models\Cipher;
use App\Models\EmergencyAccess;
use App\Models\Event;
use App\Models\Send;
use App\Models\SsoAuth;
use App\Models\TwoFactorDuoContext;
use App\Models\TwoFactorIncomplete;
use App\Models\User;
use App\Support\Dates;
use App\Support\Random;
use DateTimeImmutable;
use Illuminate\Support\Facades\File;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\Fakes\MailTransportFake;
use Tests\TestCase;

/**
 * The jobs of schedule_jobs (src/main.rs), each run with `kennword:job`,
 * against every database type.
 */
class ScheduledJobsTest extends TestCase
{
    use UsesVaultwardenDatabase;

    private MailTransportFake $mails;

    protected function vaultwardenEnvironment(): array
    {
        return ['SMTP_HOST' => 'localhost', 'SMTP_FROM' => 'vault@example.com'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->mails = new MailTransportFake;
        $this->app->instance(Transport::class, $this->mails);
    }

    #[DataProvider('drivers')]
    #[Parity('job:send_purge')]
    public function test_send_purge(string $driver): void
    {
        $this->useDatabase($driver);
        $user = $this->user('sally@example.com', 'Sally');
        $expired = $this->send($user, Send::TYPE_FILE, '-1 minute');
        $kept = $this->send($user, Send::TYPE_TEXT, '+1 minute');
        $folder = app(Config::class)->path('sends_folder')."/{$expired->uuid}";
        File::ensureDirectoryExists($folder);
        File::put("{$folder}/file", 'encrypted');
        $revision = $this->backdateRevision($user);

        $this->runJob('send_purge');

        $this->assertNull(Send::findByUuid($expired->uuid));
        $this->assertDirectoryDoesNotExist($folder);
        $this->assertNotNull(Send::findByUuid($kept->uuid));
        $this->assertGreaterThan($revision, $this->revisionOf($user));
    }

    #[DataProvider('drivers')]
    #[Parity('job:trash_purge')]
    #[Parity('config:TRASH_AUTO_DELETE_DAYS')]
    public function test_trash_purge(string $driver): void
    {
        $this->useDatabase($driver);
        $user = $this->user('tom@example.com', 'Tom');
        $old = $this->cipher($user, '-31 days');
        $recent = $this->cipher($user, '-29 days');
        $active = $this->cipher($user, null);

        // Without TRASH_AUTO_DELETE_DAYS, or with 0, the trash is kept.
        $this->runJob('trash_purge');
        $this->changeVaultwardenEnvironment(['TRASH_AUTO_DELETE_DAYS' => '0']);
        $this->runJob('trash_purge');
        $this->assertNotNull(Cipher::findByUuid($old->uuid));

        $this->changeVaultwardenEnvironment(['TRASH_AUTO_DELETE_DAYS' => '30']);
        $this->runJob('trash_purge');
        $this->assertNull(Cipher::findByUuid($old->uuid));
        $this->assertNotNull(Cipher::findByUuid($recent->uuid));
        $this->assertNotNull(Cipher::findByUuid($active->uuid));
    }

    #[DataProvider('drivers')]
    #[Parity('job:incomplete_2fa')]
    #[Parity('config:INCOMPLETE_2FA_TIME_LIMIT')]
    public function test_incomplete_2fa(string $driver): void
    {
        $this->useDatabase($driver);
        $user = $this->user('ivy@example.com', 'Ivy');
        $other = $this->user('ian@example.com', 'Ian');
        $this->incompleteLogin($user, 'device-1', '-4 minutes');
        $this->incompleteLogin($other, 'device-2', '-2 minutes');

        // A mail that fails keeps the login for the next run.
        $this->mails->failure = 'SMTP is down';
        $this->runJob('incomplete_2fa');
        $this->assertNotNull(TwoFactorIncomplete::findByUserAndDevice($user->uuid, 'device-1'));

        $this->mails->failure = null;
        $this->runJob('incomplete_2fa');
        $this->assertCount(1, $this->mails->sent);
        $mail = $this->mails->last('ivy@example.com');
        $this->assertSame('Incomplete Two-Step Login From Firefox', $mail['subject']);
        $this->assertStringContainsString('203.0.113.7', $mail['text']);
        $this->assertStringContainsString('within 3 minutes', $mail['text']);
        $this->assertNull(TwoFactorIncomplete::findByUserAndDevice($user->uuid, 'device-1'));
        // Within the time limit.
        $this->assertNotNull(TwoFactorIncomplete::findByUserAndDevice($other->uuid, 'device-2'));

        // A time limit of 0 turns the mails off.
        $this->changeVaultwardenEnvironment(['INCOMPLETE_2FA_TIME_LIMIT' => '0']);
        $this->incompleteLogin($user, 'device-3', '-10 minutes');
        $this->runJob('incomplete_2fa');
        $this->assertCount(1, $this->mails->sent);
        $this->assertNotNull(TwoFactorIncomplete::findByUserAndDevice($user->uuid, 'device-3'));

        // So does turning mail off.
        $this->changeVaultwardenEnvironment(['INCOMPLETE_2FA_TIME_LIMIT' => '1', '_ENABLE_SMTP' => 'false']);
        $this->runJob('incomplete_2fa');
        $this->assertCount(1, $this->mails->sent);
    }

    #[DataProvider('drivers')]
    #[Parity('job:emergency_request_timeout')]
    public function test_emergency_request_timeout(string $driver): void
    {
        $this->useDatabase($driver);
        $grantor = $this->user('grace@example.com', 'Grace');
        $grantee = $this->user('gus@example.com', 'Gus');
        $due = $this->access($grantor, $grantee, EmergencyAccess::STATUS_RECOVERY_INITIATED, 2, '-3 days');
        $waiting = $this->access($grantor, $grantee, EmergencyAccess::STATUS_RECOVERY_INITIATED, 2, '-1 day');
        $invalid = $this->access($grantor, $grantee, EmergencyAccess::STATUS_RECOVERY_INITIATED, 0, '-3 days');
        $confirmed = $this->access($grantor, $grantee, EmergencyAccess::STATUS_CONFIRMED, 2, '-3 days');

        $this->changeVaultwardenEnvironment(['EMERGENCY_ACCESS_ALLOWED' => 'false']);
        $this->runJob('emergency_request_timeout');
        $this->assertSame(EmergencyAccess::STATUS_RECOVERY_INITIATED, $this->statusOf($due));

        $this->changeVaultwardenEnvironment(['EMERGENCY_ACCESS_ALLOWED' => 'true']);
        $revision = $this->backdateRevision($grantee);
        $this->runJob('emergency_request_timeout');

        $this->assertSame(EmergencyAccess::STATUS_RECOVERY_APPROVED, $this->statusOf($due));
        $this->assertGreaterThan($revision, $this->revisionOf($grantee));
        $this->assertSame(EmergencyAccess::STATUS_RECOVERY_INITIATED, $this->statusOf($waiting));
        $this->assertSame(EmergencyAccess::STATUS_RECOVERY_INITIATED, $this->statusOf($invalid));
        $this->assertSame(EmergencyAccess::STATUS_CONFIRMED, $this->statusOf($confirmed));

        $this->assertCount(2, $this->mails->sent);
        $timedOut = $this->mails->last('grace@example.com');
        $this->assertSame('Emergency access request by Gus granted', $timedOut['subject']);
        $this->assertStringContainsString('access to Takeover your account', $timedOut['text']);
        $this->assertSame('Emergency access request for Grace approved', $this->mails->last('gus@example.com')['subject']);
    }

    #[DataProvider('drivers')]
    #[Parity('job:emergency_notification_reminder')]
    public function test_emergency_notification_reminder(string $driver): void
    {
        $this->useDatabase($driver);
        $grantor = $this->user('grace@example.com', 'Grace');
        $grantee = $this->user('gus@example.com', 'Gus');
        // Reminders go out during the last day, at most once a day.
        $lastDay = $this->access($grantor, $grantee, EmergencyAccess::STATUS_RECOVERY_INITIATED, 2, '-36 hours');
        $remindedYesterday = $this->access($grantor, $grantee, EmergencyAccess::STATUS_RECOVERY_INITIATED, 3, '-60 hours', '-25 hours');
        $remindedToday = $this->access($grantor, $grantee, EmergencyAccess::STATUS_RECOVERY_INITIATED, 3, '-60 hours', '-23 hours');
        $early = $this->access($grantor, $grantee, EmergencyAccess::STATUS_RECOVERY_INITIATED, 2, '-12 hours');
        $overdue = $this->access($grantor, $grantee, EmergencyAccess::STATUS_RECOVERY_INITIATED, 2, '-3 days');

        // MySQL keeps whole seconds.
        $start = Dates::now()->modify('-1 second');
        $this->runJob('emergency_notification_reminder');

        $this->assertCount(2, $this->mails->sent);
        $mail = $this->mails->last('grace@example.com');
        $this->assertSame('Emergency access request by Gus is pending', $mail['subject']);
        $this->assertStringContainsString('automatically be approved after 1 day(s)', $mail['text']);
        foreach ([$lastDay, $remindedYesterday] as $access) {
            $notified = $this->fresh($access)->last_notification_at;
            $this->assertNotNull($notified);
            $this->assertGreaterThanOrEqual($start, $notified);
        }
        $this->assertNull($this->fresh($early)->last_notification_at);
        $this->assertNull($this->fresh($overdue)->last_notification_at);
        $this->assertLessThan($start, $this->fresh($remindedToday)->last_notification_at);

        // Not again on the same day.
        $this->runJob('emergency_notification_reminder');
        $this->assertCount(2, $this->mails->sent);
    }

    #[DataProvider('drivers')]
    #[Parity('job:auth_request_purge')]
    public function test_auth_request_purge(string $driver): void
    {
        $this->useDatabase($driver);
        $user = $this->user('ada@example.com', 'Ada');
        $expired = $this->authRequest($user, '-16 minutes');
        $pending = $this->authRequest($user, '-14 minutes');

        $this->runJob('auth_request_purge');

        $this->assertFalse(AuthRequest::query()->whereKey($expired)->exists());
        $this->assertTrue(AuthRequest::query()->whereKey($pending)->exists());
    }

    #[DataProvider('drivers')]
    #[Parity('job:duo_context_purge')]
    public function test_duo_context_purge(string $driver): void
    {
        $this->useDatabase($driver);
        TwoFactorDuoContext::query()->insert([
            ['state' => 'expired', 'user_email' => 'duo@example.com', 'nonce' => 'n1', 'exp' => time() - 1],
            ['state' => 'pending', 'user_email' => 'duo@example.com', 'nonce' => 'n2', 'exp' => time() + 300],
        ]);

        $this->runJob('duo_context_purge');

        $this->assertNull(TwoFactorDuoContext::findByState('expired'));
        $this->assertNotNull(TwoFactorDuoContext::findByState('pending'));
    }

    #[DataProvider('drivers')]
    #[Parity('job:event_cleanup')]
    #[Parity('config:EVENTS_DAYS_RETAIN')]
    public function test_event_cleanup(string $driver): void
    {
        $this->useDatabase($driver);
        $old = Event::new(1000, Dates::now()->modify('-31 days'));
        $old->save();
        $recent = Event::new(1000, Dates::now()->modify('-29 days'));
        $recent->save();

        // Events are kept without a retention.
        $this->runJob('event_cleanup');
        $this->assertTrue(Event::query()->whereKey($old->uuid)->exists());

        $this->changeVaultwardenEnvironment(['EVENTS_DAYS_RETAIN' => '30']);
        $this->runJob('event_cleanup');
        $this->assertFalse(Event::query()->whereKey($old->uuid)->exists());
        $this->assertTrue(Event::query()->whereKey($recent->uuid)->exists());
    }

    #[DataProvider('drivers')]
    #[Parity('job:purge_incomplete_sso_auth')]
    public function test_purge_incomplete_sso_auth(string $driver): void
    {
        $this->useDatabase($driver);
        foreach (['expired' => '-11 minutes', 'pending' => '-9 minutes'] as $state => $age) {
            $created = NaiveDateTime::format(Dates::now()->modify($age));
            SsoAuth::query()->insert([
                'state' => $state, 'client_challenge' => 'challenge', 'nonce' => 'nonce', 'redirect_uri' => 'https://vault.example.com/sso-connector.html',
                'created_at' => $created, 'updated_at' => $created,
            ]);
        }

        $this->runJob('purge_incomplete_sso_auth');

        $this->assertSame(['pending'], SsoAuth::query()->pluck('state')->all());
    }

    public function test_unknown_jobs_are_refused(): void
    {
        $this->command('kennword:job', ['job' => 'nothing'])->expectsOutputToContain('Unknown job.')->assertFailed();
    }

    private function runJob(string $job): void
    {
        $this->command('kennword:job', ['job' => $job])->assertSuccessful();
    }

    private function user(string $email, string $name): User
    {
        $user = User::new($email, $name);
        $user->save();

        return $user;
    }

    /**
     * An hour back, so that a new revision shows even where timestamps keep whole seconds.
     */
    private function backdateRevision(User $user): DateTimeImmutable
    {
        User::query()->whereKey($user->uuid)->update(['updated_at' => NaiveDateTime::format(Dates::now()->modify('-1 hour'))]);

        return $this->revisionOf($user);
    }

    private function revisionOf(User $user): DateTimeImmutable
    {
        $stored = User::findByUuid($user->uuid);
        $this->assertNotNull($stored);

        return $stored->updated_at;
    }

    private function send(User $user, int $type, string $deletion): Send
    {
        $send = Send::new($type, 'name', '{}', 'key', Dates::now()->modify($deletion));
        $send->user_uuid = $user->uuid;
        $send->save();

        return $send;
    }

    private function cipher(User $user, ?string $deleted): Cipher
    {
        $cipher = Cipher::new(1, 'name');
        $cipher->user_uuid = $user->uuid;
        $cipher->deleted_at = $deleted === null ? null : Dates::now()->modify($deleted);
        $cipher->save();

        return $cipher;
    }

    private function incompleteLogin(User $user, string $device, string $age): void
    {
        TwoFactorIncomplete::query()->insert([
            'user_uuid' => $user->uuid,
            'device_uuid' => $device,
            'device_name' => 'firefox',
            'device_type' => 10,
            'login_time' => NaiveDateTime::format(Dates::now()->modify($age)),
            'ip_address' => '203.0.113.7',
        ]);
    }

    private function access(User $grantor, User $grantee, int $status, int $waitTimeDays, string $initiated, ?string $notified = null): EmergencyAccess
    {
        $now = Dates::now();
        $access = new EmergencyAccess([
            'uuid' => Random::uuid(),
            'grantor_uuid' => $grantor->uuid,
            'grantee_uuid' => $grantee->uuid,
            'email' => null,
            'key_encrypted' => 'key',
            'atype' => EmergencyAccess::TYPE_TAKEOVER,
            'status' => $status,
            'wait_time_days' => $waitTimeDays,
            'recovery_initiated_at' => $now->modify($initiated),
            'last_notification_at' => $notified === null ? null : $now->modify($notified),
            'updated_at' => $now,
            'created_at' => $now,
        ]);
        $access->save();

        return $access;
    }

    private function fresh(EmergencyAccess $access): EmergencyAccess
    {
        $stored = EmergencyAccess::query()->whereKey($access->uuid)->first();
        $this->assertNotNull($stored);

        return $stored;
    }

    private function statusOf(EmergencyAccess $access): int
    {
        return $this->fresh($access)->status;
    }

    private function authRequest(User $user, string $age): string
    {
        $uuid = Random::uuid();
        AuthRequest::query()->insert([
            'uuid' => $uuid,
            'user_uuid' => $user->uuid,
            'organization_uuid' => null,
            'request_device_identifier' => Random::uuid(),
            'device_type' => 10,
            'request_ip' => '203.0.113.7',
            'response_device_id' => null,
            'access_code' => 'code',
            'public_key' => 'key',
            'enc_key' => null,
            'master_password_hash' => null,
            'approved' => null,
            'creation_date' => NaiveDateTime::format(Dates::now()->modify($age)),
            'response_date' => null,
            'authentication_date' => null,
        ]);

        return $uuid;
    }
}
