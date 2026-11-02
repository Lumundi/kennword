<?php

namespace Tests\Differential;

use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Attributes\Parity;

/**
 * The icon service against the fake websites of .github/scripts/fake-websites.php,
 * which differential.sh serves on ports 80 and 443: the pair with groups and
 * events fetches them (non-global addresses allowed, "blocked." hosts
 * blocked, a three-second timeout), the default pair refuses local
 * addresses, and the SSO pair redirects to an external service. Besides the
 * answers, each flow compares what the servers keep in ICON_CACHE_FOLDER.
 */
#[Parity('route:GET /icons/{host}/icon.png')]
#[Parity('route:GET /icons/{host}/icon.png#icon_external')]
class IconsTest extends DifferentialTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (! getenv('VW_WEBSITES_STATE')) {
            $this->markTestSkipped('The fake websites are not running (differential.sh needs ports 80 and 443).');
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function websites(): iterable
    {
        $sites = [
            // The best of several links; only a favicon.ico.
            'links.icons.localhost', 'favicon.icons.localhost',
            // Redirects for page and icon; four are followed, not five.
            'redirect.icons.localhost', 'fourhops.icons.localhost', 'fivehops.icons.localhost',
            // HTTP when HTTPS fails, the domain without subdomains, www. in front.
            'httponly.icons.localhost', 'missing.icons.localhost', 'wwwonly.localhost',
            // Broken icons before a good one, only broken ones, too big ones, too big pages, too slow icons.
            'broken.icons.localhost', 'allbroken.icons.localhost', 'oversized.icons.localhost', 'bigpage.icons.localhost',
            'slowicon.icons.localhost',
            // SVG, filtered or broken; icons in data: URLs; every image type.
            'svg.icons.localhost', 'brokensvg.icons.localhost', 'datauri.icons.localhost', 'gif.icons.localhost',
            'jpeg.icons.localhost', 'webp.icons.localhost', 'bmp.icons.localhost',
            // What the tokenizer must get right.
            'tricky.icons.localhost', 'entities.icons.localhost', 'dupes.icons.localhost', 'quirk.icons.localhost',
            'basename.icons.localhost', 'baseattr.icons.localhost',
            // Compressed and chunked answers, a cookie check.
            'gzip.icons.localhost', 'chunked.icons.localhost', 'cookie.icons.localhost',
            // Blocked hosts, links to blocked and invalid hosts, an address, an invalid name.
            'blocked.icons.localhost', 'linkblocked.icons.localhost', 'invalidlink.icons.localhost', '127.0.0.1', 'dead_beaf.cafe',
        ];
        foreach ($sites as $site) {
            yield $site => [$site];
        }
    }

    #[DataProvider('websites')]
    #[Parity('config:ICON_DOWNLOAD_TIMEOUT')]
    #[Parity('config:HTTP_REQUEST_BLOCK_REGEX')]
    public function test_icons_of_websites(string $host): void
    {
        $this->assertSameFlowsOn((string) getenv('VW_FEATURES_REFERENCE_URL'), (string) getenv('VW_FEATURES_SUBJECT_URL'),
            fn (Server $server): array => [
                'download' => $server->send('GET', "/icons/{$host}/icon.png"),
                'again' => $server->send('GET', "/icons/{$host}/icon.png"),
                'cache' => $this->cacheFiles($server, $host),
            ]);
    }

    #[Parity('config:ICON_CACHE_NEGTTL')]
    public function test_failures_are_remembered(): void
    {
        $host = 'negative.localhost';
        $this->assertSameFlowsOn((string) getenv('VW_FEATURES_REFERENCE_URL'), (string) getenv('VW_FEATURES_SUBJECT_URL'),
            function (Server $server) use ($host): array {
                $steps = [];
                $this->switchSite($host, null);
                $steps['fails'] = $server->send('GET', "/icons/{$host}/icon.png");
                $steps['marked'] = $this->cacheFiles($server, $host);
                $this->switchSite($host, 'up');
                $steps['not tried again'] = $server->send('GET', "/icons/{$host}/icon.png");
                touch($this->cacheFolder($server)."/{$host}.png.miss", time() - 259_200);
                $steps['tried after ICON_CACHE_NEGTTL'] = $server->send('GET', "/icons/{$host}/icon.png");
                $steps['cached'] = $this->cacheFiles($server, $host);
                $this->switchSite($host, null);

                return $steps;
            });
    }

    #[Parity('config:ICON_CACHE_TTL')]
    #[Parity('config:ICON_CACHE_FOLDER')]
    public function test_icons_are_cached(): void
    {
        $host = 'cached.icons.localhost';
        $this->assertSameFlowsOn((string) getenv('VW_FEATURES_REFERENCE_URL'), (string) getenv('VW_FEATURES_SUBJECT_URL'),
            function (Server $server) use ($host): array {
                $steps = [];
                $this->switchSite($host, 'first');
                $steps['downloaded'] = $server->send('GET', "/icons/{$host}/icon.png");
                $this->switchSite($host, 'second');
                $steps['from the cache'] = $server->send('GET', "/icons/{$host}/icon.png");
                touch($this->cacheFolder($server)."/{$host}.png", time() - 2_592_000);
                $steps['downloaded after ICON_CACHE_TTL'] = $server->send('GET', "/icons/{$host}/icon.png");
                $steps['cached'] = $this->cacheFiles($server, $host);
                $this->switchSite($host, null);

                return $steps;
            });
    }

    #[Parity('config:HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS')]
    public function test_local_addresses_are_blocked_by_default(): void
    {
        $this->assertSameFlows(fn (Server $server): array => [
            'a name of a local address' => $server->send('GET', '/icons/links.icons.localhost/icon.png'),
            'a local address' => $server->send('GET', '/icons/127.0.0.1/icon.png'),
            'in decimal' => $server->send('GET', '/icons/2130706433/icon.png'),
            'in IPv6' => $server->send('GET', '/icons/[::1]/icon.png'),
            'an invalid host' => $server->send('GET', '/icons/dead_beaf.cafe/icon.png'),
            'cache' => $this->cacheFiles($server, 'links.icons.localhost'),
            'cache of the address' => $this->cacheFiles($server, '127.0.0.1'),
        ]);
    }

    #[Parity('config:ICON_SERVICE')]
    #[Parity('config:ICON_REDIRECT_CODE')]
    #[Parity('config:_ICON_SERVICE_URL')]
    #[Parity('config:_ICON_SERVICE_CSP')]
    public function test_an_external_icon_service(): void
    {
        $this->assertSameFlowsOn((string) getenv('VW_SSO_REFERENCE_URL'), (string) getenv('VW_SSO_SUBJECT_URL'), fn (Server $server): array => [
            'a domain' => $server->send('GET', '/icons/example.com/icon.png'),
            'an international domain' => $server->send('GET', '/icons/B%C3%BCcher.example/icon.png'),
            'an IPv6 address' => $server->send('GET', '/icons/[2001:4860::8888]/icon.png'),
            'a local address' => $server->send('GET', '/icons/127.0.0.1/icon.png'),
            'an invalid host' => $server->send('GET', '/icons/dead_beaf.cafe/icon.png'),
            'HEAD' => $server->send('HEAD', '/icons/example.com/icon.png'),
        ]);
    }

    /**
     * The files the server keeps for the host, with a hash of their contents.
     */
    private function cacheFiles(Server $server, string $host): Exchange
    {
        $files = [];
        foreach (["{$host}.png", "{$host}.png.miss"] as $name) {
            $path = $this->cacheFolder($server)."/{$name}";
            if (is_file($path)) {
                $files[$name] = hash_file('sha256', $path);
            }
        }

        return new Exchange(200, [], (string) json_encode($files, JSON_PRETTY_PRINT));
    }

    private function cacheFolder(Server $server): string
    {
        foreach (['REFERENCE', 'SUBJECT', 'FEATURES_REFERENCE', 'FEATURES_SUBJECT'] as $pair) {
            if (getenv("VW_{$pair}_URL") === $server->baseUrl) {
                return (string) getenv("VW_{$pair}_ICONS");
            }
        }

        throw new \RuntimeException("No icon cache known for {$server->baseUrl}.");
    }

    /**
     * Which variant a switchable site serves; null for the first.
     */
    private function switchSite(string $host, ?string $variant): void
    {
        $file = getenv('VW_WEBSITES_STATE')."/{$host}";
        if ($variant === null) {
            @unlink($file);
        } else {
            file_put_contents($file, $variant);
        }
    }
}
