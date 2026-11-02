<?php

namespace App\Console\Commands;

use App\Database\VaultwardenMigrator;
use App\Models\TwoFactor;
use Illuminate\Console\Command;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Facades\File;

class VaultwardenMigrate extends Command
{
    /**
     * @var string
     */
    protected $signature = 'kennword:migrate {--database= : The database connection to use}';

    /**
     * @var string
     */
    protected $description = 'Run pending Vaultwarden schema migrations and convert old two-factor data';

    public function handle(DatabaseManager $databases, VaultwardenMigrator $migrator): int
    {
        $name = $this->option('database');
        $connection = $databases->connection(is_string($name) ? $name : null);

        // Like Vaultwarden, create a missing SQLite database file on first start.
        $file = $connection->getConfig('database');
        if ($connection->getDriverName() === 'sqlite' && is_string($file) && $file !== ':memory:' && ! File::exists($file)) {
            File::ensureDirectoryExists(dirname($file));
            File::put($file, '');
        }

        $applied = $migrator->migrate($connection);

        // Vaultwarden converts old two-factor data at every start.
        if (is_string($name)) {
            $databases->setDefaultConnection($name);
        }
        TwoFactor::migrateU2fToWebauthn();
        TwoFactor::migrateCredentialToPasskey();

        if ($applied === []) {
            $this->components->info('Nothing to migrate.');

            return self::SUCCESS;
        }

        foreach ($applied as $migration) {
            $this->components->twoColumnDetail($migration, '<fg=green;options=bold>DONE</>');
        }

        $this->components->info(count($applied).' migrations applied.');

        return self::SUCCESS;
    }
}
