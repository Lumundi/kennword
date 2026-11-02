<?php

namespace Tests\Feature\Console;

use App\Console\Commands\ReleaseBuild;
use App\Support\Downloader;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\Process;
use PharData;
use PharFileInfo;
use RecursiveIteratorIterator;
use RuntimeException;
use Tests\Fakes\DownloaderFake;
use Tests\TestCase;

/**
 * release:build with git, Composer, the web vault and GitHub faked: the checkout
 * is a few files of the repository, Composer and the web vault leave a file
 * each, and GitHub answers with the source archives of the web vault.
 */
class ReleaseBuildTest extends TestCase
{
    private const string COMMIT = '0123456789abcdef0123456789abcdef01234567';

    /**
     * Files of the checkout that the archives keep: some of what the
     * installation reads, and the licenses that travel with the code.
     */
    private const array KEPT = ['.env.example', 'LICENSE.txt', 'LICENSES/GPL-3.0.txt', 'NOTICE.md', 'artisan', 'database/vaultwarden/sqlite', 'parity/reference.json', 'parity/schema/sqlite.json'];

    private const array SOURCES = [
        'https://github.com/vaultwarden/vw_web_builds/archive/refs/tags/v2026.10.1%2B0.tar.gz' => 'web-vault-2026.10.1-source-vw_web_builds.tar.gz',
        'https://github.com/dani-garcia/bw_web_builds/archive/refs/tags/v2026.10.1.tar.gz' => 'web-vault-2026.10.1-source-bw_web_builds.tar.gz',
    ];

    private string $output;

    private DownloaderFake $downloads;

    protected function setUp(): void
    {
        parent::setUp();
        $this->output = "{$this->dataFolder}/build";
        $this->downloads = new DownloaderFake;
        foreach (array_keys(self::SOURCES) as $url) {
            $this->downloads->responses[$url] = [200, "\x1f\x8b{$url}"];
        }
        $this->app->instance(Downloader::class, $this->downloads);

        Process::fake([
            "*'rev-parse'*" => self::COMMIT."\n",
            "*'show'*" => "1793363696\n",
            "*'status'*" => '',
            "*'clone'*" => function (PendingProcess $process): string {
                $command = (array) $process->command;
                $staging = (string) end($command);
                foreach ([...self::KEPT, 'tests/Unit/ExampleTest.php', '.github/workflows/tests.yml', 'parity/matrix.json', 'AGENTS.md'] as $path) {
                    @mkdir(dirname("{$staging}/{$path}"), recursive: true);
                    file_put_contents("{$staging}/{$path}", $path === 'parity/reference.json' ? (string) file_get_contents(base_path($path)) : $path);
                }
                mkdir("{$staging}/.git");

                return '';
            },
            "*'checkout'*" => '',
            "*'install'*" => function (PendingProcess $process): string {
                mkdir("{$process->path}/vendor");
                file_put_contents("{$process->path}/vendor/autoload.php", '<?php');

                return '';
            },
            "*'vaultwarden:web-vault'*" => function (PendingProcess $process): string {
                $folder = $process->environment['WEB_VAULT_FOLDER'];
                $this->assertIsString($folder);
                mkdir($folder);
                file_put_contents("{$folder}/index.html", '<!DOCTYPE html>');

                return '';
            },
            '*Release::installed*' => "1.0.0\n",
            "*'clean'*" => '',
        ]);
    }

    public function test_it_packs_the_checkout_with_its_dependencies_and_the_web_vault(): void
    {
        $this->command('release:build', ['ref' => 'v1.0.0', '--output' => $this->output, '--composer' => '/usr/bin/composer'])
            ->expectsOutputToContain('Built kennword-1.0.0 from '.self::COMMIT)
            ->assertSuccessful();

        $this->assertSame([
            '.', '..',
            'kennword-1.0.0.sha256', 'kennword-1.0.0.tar.gz', 'kennword-1.0.0.zip',
            'web-vault-2026.10.1-source-bw_web_builds.tar.gz', 'web-vault-2026.10.1-source-vw_web_builds.tar.gz',
        ], scandir($this->output));
        $sums = '';
        foreach (['kennword-1.0.0.tar.gz', 'kennword-1.0.0.zip', ...array_values(self::SOURCES)] as $file) {
            $sums .= hash_file('sha256', "{$this->output}/{$file}")."  {$file}\n";
        }
        $this->assertSame($sums, file_get_contents("{$this->output}/kennword-1.0.0.sha256"));
        foreach (self::SOURCES as $url => $file) {
            $this->assertSame("\x1f\x8b{$url}", file_get_contents("{$this->output}/{$file}"));
        }

        // Phar names the entries below the real path of the archive.
        $prefix = 'phar://'.realpath("{$this->output}/kennword-1.0.0.tar.gz").'/kennword-1.0.0/';
        $files = [];
        foreach (new RecursiveIteratorIterator(new PharData("{$this->output}/kennword-1.0.0.tar.gz")) as $file) {
            $this->assertInstanceOf(PharFileInfo::class, $file);
            $files[] = substr($file->getPathname(), strlen($prefix));
        }
        $expected = [...self::KEPT, 'vendor/autoload.php', 'web-vault/index.html'];
        sort($files);
        sort($expected);
        $this->assertSame($expected, $files);

        Process::assertRan(fn (PendingProcess $process): bool => is_array($process->command)
            && array_slice($process->command, 1, 5) === ['/usr/bin/composer', 'install', '--no-dev', '--optimize-autoloader', '--prefer-dist']
            && $process->environment === ['COMPOSER_ROOT_VERSION' => false]);
        Process::assertRan(fn (PendingProcess $process): bool => is_array($process->command)
            && array_slice($process->command, 0, 4) === ['git', 'clean', '-d', '--force']
            && in_array('--exclude=/vendor', $process->command, true) && in_array('--exclude=/web-vault', $process->command, true));
    }

    public function test_it_names_a_build_without_a_tag_after_the_commit(): void
    {
        Process::fake(['*Release::installed*' => "-\n"]);

        $this->command('release:build', ['--output' => $this->output, '--composer' => '/usr/bin/composer'])->assertSuccessful();

        $this->assertFileExists("{$this->output}/kennword-01234567.tar.gz");
    }

    public function test_it_fails_without_the_source_of_the_web_vault(): void
    {
        $this->downloads->responses = [];

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('GitHub answered 404 without an archive for vaultwarden/vw_web_builds v2026.10.1+0.');
        $this->command('release:build', ['--output' => $this->output, '--composer' => '/usr/bin/composer'])->run();
    }

    public function test_it_refuses_an_unknown_ref(): void
    {
        Process::fake(["*'rev-parse'*" => Process::result(exitCode: 1)]);

        $this->command('release:build', ['ref' => 'nope', '--output' => $this->output])
            ->expectsOutputToContain('There is no commit nope.')
            ->assertFailed();
    }

    public function test_what_it_leaves_out_or_keeps_is_in_the_repository(): void
    {
        foreach ([...ReleaseBuild::LEFT_OUT, ...self::KEPT] as $path) {
            $this->assertFileExists(base_path($path));
        }
    }
}
