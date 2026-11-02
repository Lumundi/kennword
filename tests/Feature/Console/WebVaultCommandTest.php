<?php

namespace Tests\Feature\Console;

use App\Config\Config;
use App\Support\WebVault;
use App\Support\WebVaultImage;
use Phar;
use PharData;
use Tests\Fakes\DownloaderFake;
use Tests\TestCase;

/**
 * kennword:web-vault, with the registries faked: an image like
 * bw_web_builds' (the archive in one layer, the web-vault folder in the next),
 * indexed for linux/amd64 and an attestation.
 */
class WebVaultCommandTest extends TestCase
{
    private DownloaderFake $downloads;

    private string $webVault;

    /**
     * The responses of a registry for the image, by URL.
     *
     * @var array<string, array{int, string}>
     */
    private array $image = [];

    private string $digest;

    /**
     * The digests of the image for linux/amd64 and of its layers.
     *
     * @var array{string, string, string}
     */
    private array $digests;

    protected function vaultwardenEnvironment(): array
    {
        return ['WEB_VAULT_FOLDER' => "{$this->dataFolder}/web-vault/"];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->webVault = "{$this->dataFolder}/web-vault";

        $layers = [
            $this->layer(0, ['bw_web_vault.tar.gz' => 'the same files once more', 'web-vault/app/main.js' => 'console.log(0);']),
            $this->layer(1, [
                'web-vault/index.html' => '<!DOCTYPE html><title>Web vault</title>',
                'web-vault/vw-version.json' => '{"version":"2026.8.0"}',
                'web-vault/app/main.js' => 'console.log(1);',
            ]),
        ];
        $config = '{"architecture":"amd64","os":"linux"}';
        $manifest = (string) json_encode([
            'schemaVersion' => 2,
            'mediaType' => 'application/vnd.oci.image.manifest.v1+json',
            'config' => ['mediaType' => 'application/vnd.oci.image.config.v1+json', 'digest' => self::digest($config), 'size' => strlen($config)],
            'layers' => array_map(static fn (string $layer): array => [
                'mediaType' => 'application/vnd.oci.image.layer.v1.tar+gzip', 'digest' => self::digest($layer), 'size' => strlen($layer),
            ], $layers),
        ]);
        $index = (string) json_encode([
            'schemaVersion' => 2,
            'mediaType' => 'application/vnd.oci.image.index.v1+json',
            'manifests' => [
                ['digest' => self::digest('attestation'), 'platform' => ['architecture' => 'unknown', 'os' => 'unknown']],
                ['digest' => self::digest($manifest), 'platform' => ['architecture' => 'amd64', 'os' => 'linux']],
            ],
        ]);
        $this->digest = self::digest($index);
        $this->digests = [self::digest($manifest), self::digest($layers[0]), self::digest($layers[1])];
        $this->image = [
            "/manifests/{$this->digest}" => [200, $index],
            "/manifests/{$this->digests[0]}" => [200, $manifest],
            "/blobs/{$this->digests[1]}" => [200, $layers[0]],
            "/blobs/{$this->digests[2]}" => [200, $layers[1]],
        ];

        $this->downloads = new DownloaderFake;
        $this->app->instance(WebVaultImage::class, new WebVaultImage('2026.8.0', $this->digest, $this->downloads));
    }

    public function test_installs_the_web_vault_of_the_image(): void
    {
        $this->serve('ghcr.io');

        $this->command('kennword:web-vault')
            ->expectsOutputToContain("Web vault 2026.8.0 installed in {$this->webVault}.")
            ->assertSuccessful();

        // The layers are unpacked in order, and only the web-vault folder.
        $this->assertSame('<!DOCTYPE html><title>Web vault</title>', file_get_contents("{$this->webVault}/index.html"));
        $this->assertSame('console.log(1);', file_get_contents("{$this->webVault}/app/main.js"));
        $this->assertFileDoesNotExist("{$this->dataFolder}/bw_web_vault.tar.gz");
        $this->assertSame([], glob("{$this->dataFolder}/.web-vault-*"));
        $this->assertSame('2026.8.0', WebVault::activeRelease($this->app->make(Config::class)));

        $this->assertSame([
            'https://ghcr.io/token?scope=repository:dani-garcia/bw_web_builds:pull',
            "https://ghcr.io/v2/dani-garcia/bw_web_builds/manifests/{$this->digest}",
            "https://ghcr.io/v2/dani-garcia/bw_web_builds/manifests/{$this->digests[0]}",
            "https://ghcr.io/v2/dani-garcia/bw_web_builds/blobs/{$this->digests[1]}",
            "https://ghcr.io/v2/dani-garcia/bw_web_builds/blobs/{$this->digests[2]}",
        ], array_column($this->downloads->requests, 'url'));
        $this->assertSame([], $this->downloads->requests[0]['headers']);
        $this->assertSame('Bearer ghcr.io-token', $this->downloads->requests[1]['headers']['Authorization']);
        $this->assertStringStartsWith('application/vnd.oci.image.index.v1+json, ', $this->downloads->requests[1]['headers']['Accept']);
        $this->assertSame('Bearer ghcr.io-token', $this->downloads->requests[4]['headers']['Authorization']);
    }

    public function test_an_installed_version_is_kept_unless_forced(): void
    {
        $this->serve('ghcr.io');
        mkdir($this->webVault);
        file_put_contents("{$this->webVault}/vw-version.json", '{"version":"2026.8.0"}');
        file_put_contents("{$this->webVault}/old.js", 'console.log("old");');

        $this->command('kennword:web-vault')->expectsOutputToContain('Web vault 2026.8.0 is installed already.')->assertSuccessful();
        $this->assertSame([], $this->downloads->requests);

        // Forced, or after an update that pins another version, the folder is replaced as a whole.
        $this->command('kennword:web-vault', ['--force' => true])->assertSuccessful();
        $this->assertFileDoesNotExist("{$this->webVault}/old.js");
        $this->assertFileExists("{$this->webVault}/index.html");
        $this->assertSame([], glob("{$this->dataFolder}/.web-vault-*"));
    }

    public function test_docker_hub_when_ghcr_fails(): void
    {
        $this->downloads->responses['https://ghcr.io/token?scope=repository:dani-garcia/bw_web_builds:pull'] = null;
        $this->serve('docker.io');

        $this->command('kennword:web-vault')->expectsOutputToContain('Web vault 2026.8.0 installed')->assertSuccessful();

        $this->assertFileExists("{$this->webVault}/index.html");
        $this->assertSame('https://auth.docker.io/token?service=registry.docker.io&scope=repository:vaultwarden/web-vault:pull', $this->downloads->requests[1]['url']);
        $this->assertSame('Bearer docker.io-token', $this->downloads->requests[2]['headers']['Authorization']);
    }

    public function test_failures_leave_the_installed_web_vault_alone(): void
    {
        mkdir($this->webVault);
        file_put_contents("{$this->webVault}/vw-version.json", '{"version":"2026.7.0"}');
        $this->serve('ghcr.io');
        $this->serve('docker.io');
        // A layer that is not what the image pins, and a registry that is down.
        $this->downloads->responses["https://ghcr.io/v2/dani-garcia/bw_web_builds/blobs/{$this->digests[2]}"] = [200, 'something else'];
        $this->downloads->responses['https://registry-1.docker.io/v2/vaultwarden/web-vault/manifests/'.$this->digest] = [503, 'Service Unavailable'];

        $this->command('kennword:web-vault')
            ->expectsOutputToContain("The download does not match its digest {$this->digests[2]}")
            ->expectsOutputToContain("The registry answered 503 when asked for the manifest {$this->digest}")
            ->expectsOutputToContain('The web vault 2026.8.0 could not be downloaded.')
            ->expectsOutputToContain('or set WEB_VAULT_ENABLED=false to go without it.')
            ->assertFailed();

        $this->assertSame(['.', '..', 'vw-version.json'], scandir($this->webVault));
        $this->assertSame([], glob("{$this->dataFolder}/.web-vault-*"));
    }

    public function test_nothing_to_install_without_the_web_vault(): void
    {
        $this->changeVaultwardenEnvironment(['WEB_VAULT_ENABLED' => 'false']);

        $this->command('kennword:web-vault')->expectsOutputToContain('The web vault is disabled')->assertSuccessful();

        $this->assertSame([], $this->downloads->requests);
        $this->assertDirectoryDoesNotExist($this->webVault);
    }

    /**
     * Let a registry answer for the image.
     */
    private function serve(string $registry): void
    {
        [$base, $repository, $tokenUrl] = WebVaultImage::REGISTRIES[$registry];
        $this->downloads->responses[$tokenUrl] = [200, (string) json_encode(['token' => "{$registry}-token"])];
        foreach ($this->image as $path => $response) {
            $this->downloads->responses["{$base}/v2/{$repository}{$path}"] = $response;
        }
    }

    /**
     * A gzipped tar with the files.
     *
     * @param  array<string, string>  $files
     */
    private function layer(int $index, array $files): string
    {
        $tar = new PharData("{$this->dataFolder}/layer-{$index}.tar");
        foreach ($files as $name => $content) {
            $tar->addFromString($name, $content);
        }
        $tar->compress(Phar::GZ);
        $layer = (string) file_get_contents("{$this->dataFolder}/layer-{$index}.tar.gz");
        unlink("{$this->dataFolder}/layer-{$index}.tar");
        unlink("{$this->dataFolder}/layer-{$index}.tar.gz");

        return $layer;
    }

    private static function digest(string $content): string
    {
        return 'sha256:'.hash('sha256', $content);
    }
}
