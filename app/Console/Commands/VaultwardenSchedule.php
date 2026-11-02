<?php

namespace App\Console\Commands;

use App\Config\Config;
use App\Scheduler\JobScheduler;
use App\Support\Dates;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Console\Command;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use LogicException;

class VaultwardenSchedule extends Command
{
    /**
     * @var string
     */
    protected $signature = 'kennword:schedule {--once : Run the jobs due since the previous run and stop, for a cron job every minute}';

    /**
     * @var string
     */
    protected $description = "Run Vaultwarden's scheduled jobs, checking every JOB_POLL_INTERVAL_MS";

    private const string CACHE_KEY = 'kennword:schedule';

    private bool $stopping = false;

    public function handle(Config $config, Repository $cache): int
    {
        $interval = $config->int('job_poll_interval_ms');
        if ($interval === 0) {
            $this->components->info('Job scheduler disabled.');

            return self::SUCCESS;
        }

        $scheduler = JobScheduler::fromConfig($config);
        if ($this->option('once')) {
            $this->tickOnce($scheduler, $cache);

            return self::SUCCESS;
        }

        // Stop between ticks, not in the middle of a job.
        $this->trap(fn (): array => [SIGINT, SIGTERM], function (): void {
            $this->stopping = true;
        });
        $this->components->info(sprintf('Running %d scheduled jobs, checking every %d ms.', count($scheduler->jobs), $interval));
        while (! $this->stopping) {
            $scheduler->tick();
            usleep($interval * 1000);
        }

        return self::SUCCESS;
    }

    /**
     * One tick, with the time of the previous one kept in the cache. Runs
     * that overlap are skipped.
     */
    private function tickOnce(JobScheduler $scheduler, Repository $cache): void
    {
        $store = $cache->getStore();
        if (! $store instanceof LockProvider) {
            throw new LogicException('The cache store must support locks.');
        }

        $lock = $store->lock(self::CACHE_KEY.':lock', 3600);
        if (! $lock->get()) {
            $this->components->warn('The previous run has not finished yet.');

            return;
        }

        try {
            foreach ($scheduler->jobs as $job) {
                // Microseconds since the epoch; the cache does not restore objects.
                $lastTick = $cache->get(self::CACHE_KEY.":{$job->name}");
                $job->lastTick = is_int($lastTick) ? self::fromMicroseconds($lastTick) : null;
            }

            $scheduler->tick();

            foreach ($scheduler->jobs as $job) {
                $cache->forever(self::CACHE_KEY.":{$job->name}", (int) ($job->lastTick ?? Dates::now())->format('Uu'));
            }
        } finally {
            $lock->release();
        }
    }

    private static function fromMicroseconds(int $microseconds): ?DateTimeImmutable
    {
        $date = DateTimeImmutable::createFromFormat('U.u', sprintf('%d.%06d', intdiv($microseconds, 1_000_000), $microseconds % 1_000_000), new DateTimeZone('UTC'));

        return $date === false ? null : $date;
    }
}
