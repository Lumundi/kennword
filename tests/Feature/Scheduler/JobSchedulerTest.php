<?php

namespace Tests\Feature\Scheduler;

use App\Config\Config;
use App\Models\Send;
use App\Models\User;
use App\Scheduler\Job;
use App\Scheduler\Jobs;
use App\Scheduler\JobScheduler;
use App\Support\CronSchedule;
use App\Support\Dates;
use ArrayObject;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use RuntimeException;
use Symfony\Component\Process\Process;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * schedule_jobs (src/main.rs) and job_scheduler_ng, which ticks the jobs.
 */
class JobSchedulerTest extends TestCase
{
    use UsesVaultwardenDatabase;

    #[Parity('config:JOB_POLL_INTERVAL_MS')]
    #[Parity('config:SEND_PURGE_SCHEDULE')]
    #[Parity('config:TRASH_PURGE_SCHEDULE')]
    #[Parity('config:INCOMPLETE_2FA_SCHEDULE')]
    #[Parity('config:EMERGENCY_NOTIFICATION_REMINDER_SCHEDULE')]
    #[Parity('config:EMERGENCY_REQUEST_TIMEOUT_SCHEDULE')]
    #[Parity('config:EVENT_CLEANUP_SCHEDULE')]
    #[Parity('config:AUTH_REQUEST_PURGE_SCHEDULE')]
    #[Parity('config:DUO_CONTEXT_PURGE_SCHEDULE')]
    #[Parity('config:PURGE_INCOMPLETE_SSO_AUTH')]
    public function test_the_settings_choose_the_jobs_in_vaultwardens_order(): void
    {
        $this->assertSame(
            ['send_purge', 'trash_purge', 'incomplete_2fa', 'emergency_request_timeout', 'emergency_notification_reminder', 'auth_request_purge', 'duo_context_purge', 'purge_incomplete_sso_auth'],
            $this->jobNames(),
        );

        // Event cleanup needs the event log and a retention.
        $this->changeVaultwardenEnvironment(['ORG_EVENTS_ENABLED' => 'true']);
        $this->assertNotContains('event_cleanup', $this->jobNames());
        $this->changeVaultwardenEnvironment(['EVENTS_DAYS_RETAIN' => '0']);
        $this->assertNotContains('event_cleanup', $this->jobNames());
        $this->changeVaultwardenEnvironment(['EVENTS_DAYS_RETAIN' => '30']);
        $this->assertSame(['auth_request_purge', 'duo_context_purge', 'event_cleanup', 'purge_incomplete_sso_auth'], array_slice($this->jobNames(), 5));

        // A blank schedule disables a job; Duo's also needs Duo.
        $this->changeVaultwardenEnvironment(['SEND_PURGE_SCHEDULE' => '', 'PURGE_INCOMPLETE_SSO_AUTH' => '', '_ENABLE_DUO' => 'false']);
        $this->assertSame(['trash_purge', 'incomplete_2fa', 'emergency_request_timeout', 'emergency_notification_reminder', 'auth_request_purge', 'event_cleanup'], $this->jobNames());
    }

    public function test_a_job_runs_at_most_once_per_tick_when_its_schedule_is_due(): void
    {
        $runs = new ArrayObject;
        $job = new Job('test', $this->schedule('30 * * * * *'), static function () use ($runs): void {
            $runs->append(true);
        });

        // The first tick only notes the time.
        $job->tick($this->at('12:00:00'));
        $job->tick($this->at('12:00:29'));
        $this->assertCount(0, $runs);
        $job->tick($this->at('12:00:30'));
        $this->assertCount(1, $runs);
        $job->tick($this->at('12:00:59'));
        $this->assertCount(1, $runs);
        $this->assertEquals($this->at('12:00:59'), $job->lastTick);

        // Missed times are made up for once, not one by one.
        $job->tick($this->at('15:00:00'));
        $this->assertCount(2, $runs);
        $job->tick($this->at('15:00:10'));
        $this->assertCount(2, $runs);
    }

    public function test_a_failing_job_does_not_stop_the_scheduler(): void
    {
        $job = new Job('test', $this->schedule('* * * * * *'), static function (): void {
            throw new RuntimeException('Job failed');
        });

        $job->tick($this->at('12:00:00'));
        $job->tick($this->at('12:00:01'));

        $this->assertEquals($this->at('12:00:01'), $job->lastTick);
    }

    public function test_a_poll_interval_of_zero_disables_the_scheduler(): void
    {
        $this->changeVaultwardenEnvironment(['JOB_POLL_INTERVAL_MS' => '0']);

        $this->command('kennword:schedule')->expectsOutputToContain('Job scheduler disabled.')->assertSuccessful();
        $this->command('kennword:schedule', ['--once' => true])->expectsOutputToContain('Job scheduler disabled.')->assertSuccessful();
    }

    public function test_once_ticks_from_the_time_of_the_previous_run(): void
    {
        $this->useDatabase('sqlite');
        $cache = $this->app->make(Repository::class);
        $expired = $this->expiredSend();

        // Like the first tick, the first run only notes the time.
        $this->command('kennword:schedule', ['--once' => true])->assertSuccessful();
        $this->assertNotNull(Send::findByUuid($expired->uuid));
        $lastTick = $cache->get('kennword:schedule:send_purge');
        $this->assertIsInt($lastTick);
        $this->assertEqualsWithDelta(microtime(true), $lastTick / 1_000_000, 5);

        // Sends are purged at five past every hour; two hours ago, one of them has passed.
        $this->putLastTick('send_purge', '-2 hours');
        $this->command('kennword:schedule', ['--once' => true])->assertSuccessful();
        $this->assertNull(Send::findByUuid($expired->uuid));
        $this->assertGreaterThan($lastTick, $cache->get('kennword:schedule:send_purge'));

        // A run that is still going keeps the next one from starting.
        $expired = $this->expiredSend();
        $this->putLastTick('send_purge', '-2 hours');
        $store = $cache->getStore();
        $this->assertInstanceOf(LockProvider::class, $store);
        $lock = $store->lock('kennword:schedule:lock', 60);
        $this->assertTrue($lock->get());
        $this->command('kennword:schedule', ['--once' => true])->expectsOutputToContain('The previous run has not finished yet.')->assertSuccessful();
        $this->assertNotNull(Send::findByUuid($expired->uuid));
        $lock->release();
    }

    public function test_the_scheduler_runs_until_it_is_stopped(): void
    {
        if (! extension_loaded('pcntl')) {
            $this->markTestSkipped('Stopping between ticks needs the pcntl extension.');
        }

        // Laravel traps no signals in tests, so in a process of its own.
        $process = new Process([PHP_BINARY, base_path('artisan'), 'kennword:schedule'], base_path(), [
            'APP_ENV' => 'local',
            'LOG_CHANNEL' => 'null',
            'JOB_POLL_INTERVAL_MS' => '20',
            ...array_fill_keys(array_map(strtoupper(...), Jobs::SCHEDULES), ''),
        ]);
        $process->start();
        $process->waitUntil(static fn (string $type, string $output): bool => str_contains($output, 'Running 0 scheduled jobs, checking every 20 ms.'));
        usleep(100_000);
        $this->assertTrue($process->isRunning());

        $process->signal(SIGTERM);
        $this->assertSame(0, $process->wait(), $process->getErrorOutput());
    }

    /**
     * @return list<string>
     */
    private function jobNames(): array
    {
        return array_map(static fn (Job $job): string => $job->name, JobScheduler::fromConfig($this->app->make(Config::class))->jobs);
    }

    private function schedule(string $expression): CronSchedule
    {
        $schedule = CronSchedule::parse($expression);
        $this->assertNotNull($schedule);

        return $schedule;
    }

    private function at(string $time): DateTimeImmutable
    {
        return new DateTimeImmutable("2026-10-28 {$time}", new DateTimeZone('UTC'));
    }

    private function expiredSend(): Send
    {
        $user = User::new(bin2hex(random_bytes(4)).'@example.com');
        $user->save();
        $send = Send::new(Send::TYPE_TEXT, 'name', '{}', 'key', Dates::now()->modify('-1 minute'));
        $send->user_uuid = $user->uuid;
        $send->save();

        return $send;
    }

    private function putLastTick(string $job, string $modifier): void
    {
        $this->app->make(Repository::class)->forever("kennword:schedule:{$job}", (int) Dates::now()->modify($modifier)->format('Uu'));
    }
}
