<?php

namespace App\Console\Commands;

use App\Config\Config;
use App\Support\WebVault;
use App\Support\WebVaultImage;
use Illuminate\Console\Command;
use Illuminate\Console\View\TaskResult;
use Illuminate\Support\Facades\File;
use RuntimeException;

class VaultwardenWebVault extends Command
{
    /**
     * @var string
     */
    protected $signature = 'kennword:web-vault {--force : Install it even when that version is installed already}';

    /**
     * @var string
     */
    protected $description = 'Install the web vault that Vaultwarden ships into WEB_VAULT_FOLDER';

    public function handle(Config $config, WebVaultImage $image): int
    {
        if (! $config->bool('web_vault_enabled')) {
            $this->components->info('The web vault is disabled (WEB_VAULT_ENABLED=false); nothing to install.');

            return self::SUCCESS;
        }

        $folder = rtrim($config->path('web_vault_folder'), '/');
        if (! $this->option('force') && WebVault::activeRelease($config) === $image->version) {
            $this->components->info("Web vault {$image->version} is installed already.");

            return self::SUCCESS;
        }

        // Unpack next to the folder, so that the new version replaces the old one in one step.
        $work = dirname($folder).'/.'.basename($folder).'-'.bin2hex(random_bytes(4));
        try {
            foreach (array_keys(WebVaultImage::REGISTRIES) as $registry) {
                $unpacked = $error = null;
                $this->components->task("Downloading web vault {$image->version} from {$registry}", function () use ($image, $registry, $work, &$unpacked, &$error): int {
                    try {
                        File::ensureDirectoryExists("{$work}/{$registry}");
                        $unpacked = $image->pull($registry, "{$work}/{$registry}");

                        return TaskResult::Success->value;
                    } catch (RuntimeException $exception) {
                        $error = $exception->getMessage();

                        return TaskResult::Failure->value;
                    }
                });
                if ($error !== null) {
                    $this->components->bulletList([$error]);
                }
                if ($unpacked !== null) {
                    if ((is_dir($folder) || is_link($folder)) && ! @rename($folder, "{$work}/previous")) {
                        $this->components->error("The previous web vault in {$folder} cannot be moved away.");

                        return self::FAILURE;
                    }
                    if (! @rename($unpacked, $folder)) {
                        @rename("{$work}/previous", $folder);
                        $this->components->error("The web vault cannot be moved to {$folder}.");

                        return self::FAILURE;
                    }
                    $this->components->info("Web vault {$image->version} installed in {$folder}.");

                    return self::SUCCESS;
                }
            }
        } finally {
            File::deleteDirectory($work);
        }

        $this->components->error("The web vault {$image->version} could not be downloaded.");
        $this->line('  Run `php artisan kennword:web-vault` again once the download works, unpack the web vault by hand');
        $this->line('  (see docs/installation.md), or set WEB_VAULT_ENABLED=false to go without it.');

        return self::FAILURE;
    }
}
