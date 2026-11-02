<?php

namespace App\Console\Commands;

use App\Scheduler\Jobs;
use Illuminate\Console\Command;

class VaultwardenJob extends Command
{
    /**
     * @var string
     */
    protected $signature = 'kennword:job {job : The job, named after its schedule setting, e.g. send_purge}';

    /**
     * @var string
     */
    protected $description = 'Run one of Vaultwarden\'s scheduled jobs now, whatever its schedule';

    public function handle(): int
    {
        $job = $this->argument('job');
        if (! array_key_exists($job, Jobs::SCHEDULES)) {
            $this->components->error('Unknown job. Known jobs: '.implode(', ', array_keys(Jobs::SCHEDULES)).'.');

            return self::FAILURE;
        }

        Jobs::run($job);
        $this->components->info("Ran {$job}.");

        return self::SUCCESS;
    }
}
