<?php

namespace App\Console\Commands;

use App\Parity\Reference;
use App\Release\ArchiveWriter;
use App\Support\Downloader;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Number;
use RuntimeException;
use Symfony\Component\Process\ExecutableFinder;

class ReleaseBuild extends Command
{
    /**
     * What the archives leave out of the repository: the tools, tests and
     * notes for development. `parity/reference.json` stays, the web vault
     * is installed from it.
     *
     * @var list<string>
     */
    public const array LEFT_OUT = [
        '.editorconfig',
        '.gitattributes',
        '.github',
        '.gitignore',
        'AGENTS.md',
        'CLAUDE.md',
        'CONTRIBUTING.md',
        'parity/matrix.json',
        'phpstan.neon',
        'phpunit.xml',
        'tests',
    ];

    /**
     * @var string
     */
    protected $signature = 'release:build
        {ref=HEAD : The tag, branch or commit to build}
        {--output=build : The folder that takes the archives}
        {--composer= : Composer, when it is not on the PATH}';

    /**
     * @var string
     */
    protected $description = 'Build the release archives for hosts without Composer: the code with its dependencies and the web vault';

    public function handle(Downloader $downloader): int
    {
        $ref = (string) $this->argument('ref');
        $git = Process::path(base_path());
        $commit = trim($git->run(['git', 'rev-parse', '--verify', '--quiet', "{$ref}^{commit}"])->output());
        if ($commit === '') {
            $this->components->error("There is no commit {$ref}.");

            return self::FAILURE;
        }
        $timestamp = (int) trim($git->run(['git', 'show', '--no-patch', '--format=%ct', $commit])->throw()->output());
        if ($ref === 'HEAD' && trim($git->run(['git', 'status', '--porcelain', '--untracked-files=no'])->throw()->output()) !== '') {
            $this->components->warn('The archives hold the last commit, without the changes that are not committed.');
        }

        $composer = $this->option('composer') ?? (new ExecutableFinder)->find('composer');
        if (! is_string($composer) || $composer === '') {
            $this->components->error('Composer is not on the PATH; name it with --composer.');

            return self::FAILURE;
        }

        $output = (string) $this->option('output');
        $output = str_starts_with($output, '/') ? rtrim($output, '/') : base_path(rtrim($output, '/'));
        File::ensureDirectoryExists($output);
        $staging = "{$output}/.staging-{$commit}";
        File::deleteDirectory($staging);

        try {
            $this->components->task("Checking out {$commit}", function () use ($staging, $commit): void {
                Process::timeout(600)->run(['git', 'clone', '--quiet', '--no-checkout', '--no-hardlinks', base_path(), $staging])->throw();
                Process::path($staging)->run(['git', '-c', 'advice.detachedHead=false', 'checkout', '--quiet', '--detach', $commit])->throw();
                foreach (self::LEFT_OUT as $path) {
                    File::isDirectory("{$staging}/{$path}") ? File::deleteDirectory("{$staging}/{$path}") : File::delete("{$staging}/{$path}");
                }
            });

            // Composer records the tag or commit of the checkout, which the admin panel shows as the version.
            $this->components->task('Installing the dependencies without the ones for development', function () use ($staging, $composer): void {
                Process::path($staging)->timeout(1800)->env(['COMPOSER_ROOT_VERSION' => false])
                    ->run([PHP_BINARY, $composer, 'install', '--no-dev', '--optimize-autoloader', '--prefer-dist', '--no-interaction', '--no-progress', '--no-ansi'])
                    ->throw();
            });

            $this->components->task('Installing the web vault', function () use ($staging): void {
                Process::path($staging)->timeout(1800)
                    ->env(['WEB_VAULT_ENABLED' => 'true', 'WEB_VAULT_FOLDER' => "{$staging}/web-vault/", 'DATA_FOLDER' => "{$staging}/data"])
                    ->run([PHP_BINARY, 'artisan', 'kennword:web-vault', '--force', '--no-ansi'])
                    ->throw();
            });

            // The web vault is GPL-3.0 object code: its source goes along with every release (section 6).
            $sources = [];
            $this->components->task('Fetching the source of the web vault', function () use ($staging, $output, $downloader, &$sources): void {
                $reference = Reference::load($staging);
                foreach ($reference->webVaultSource as $repository => $tag) {
                    $file = "web-vault-{$reference->webVault}-source-".basename($repository).'.tar.gz';
                    $url = "https://github.com/{$repository}/archive/refs/tags/".rawurlencode($tag).'.tar.gz';
                    $status = $downloader->download($url, [], "{$output}/{$file}");
                    if ($status !== 200 || file_get_contents("{$output}/{$file}", length: 2) !== "\x1f\x8b") {
                        throw new RuntimeException("GitHub answered {$status} without an archive for {$repository} {$tag}.");
                    }
                    $sources[] = $file;
                }
            });

            $version = trim(Process::path($staging)
                ->run([PHP_BINARY, '-r', 'require "vendor/autoload.php"; echo App\Support\Release::installed();'])
                ->throw()->output());
            $name = 'kennword-'.($version === '-' ? substr($commit, 0, 8) : $version);

            // Leave what the installation wrote besides the dependencies and the web vault (caches, logs) and git.
            Process::path($staging)->run(['git', 'clean', '-d', '--force', '-x', '--quiet', '--exclude=/vendor', '--exclude=/web-vault'])->throw();
            File::deleteDirectory("{$staging}/.git");

            $archives = new ArchiveWriter($staging, $name, $timestamp);
            $files = ["{$name}.tar.gz", "{$name}.zip"];
            $this->components->task("Packing {$files[0]}", fn () => $archives->writeTarGz("{$output}/{$files[0]}"));
            $this->components->task("Packing {$files[1]}", fn () => $archives->writeZip("{$output}/{$files[1]}"));
        } finally {
            File::deleteDirectory($staging);
        }

        // In the format of sha256sum, so that `sha256sum -c` checks the downloads.
        $sums = '';
        foreach ([...$files, ...$sources] as $file) {
            $hash = (string) hash_file('sha256', "{$output}/{$file}");
            $sums .= "{$hash}  {$file}\n";
            $this->components->twoColumnDetail($file, Number::fileSize((int) filesize("{$output}/{$file}"), 1)." <fg=gray>sha256:{$hash}</>");
        }
        File::put("{$output}/{$name}.sha256", $sums);
        $this->components->info("Built {$name} from {$commit} in {$output}.");

        return self::SUCCESS;
    }
}
