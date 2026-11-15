<?php

namespace Tests\Feature\Api;

use App\Config\Config;
use App\Icons\IconClient;
use App\Support\BlockedHost;
use Tests\Attributes\Parity;
use Tests\Fakes\IconClientFake;
use Tests\TestCase;

/**
 * The internal icon service (src/api/icons.rs) against fake websites.
 */
#[Parity('route:GET /icons/{host}/icon.png')]
#[Parity('config:ICON_CACHE_FOLDER')]
#[Parity('config:ICON_CACHE_TTL')]
#[Parity('config:ICON_CACHE_NEGTTL')]
#[Parity('config:DISABLE_ICON_DOWNLOAD')]
class IconsTest extends TestCase
{
    private const string PNG = "\x89PNG\r\n\x1A\n";

    private IconClientFake $sites;

    private string $cache;

    protected function setUp(): void
    {
        parent::setUp();
        $this->sites = new IconClientFake($this->app->make(Config::class));
        $this->app->instance(IconClient::class, $this->sites);
        $this->cache = "{$this->dataFolder}/icon_cache";
    }

    public function test_the_best_icon_is_downloaded_and_cached(): void
    {
        $this->sites->answer('https://example.com', '<link rel=icon href=/small.png sizes=16x16><link rel=icon href=/best.png sizes=32x32>')
            ->answer('https://example.com/best.png', self::PNG.'best');

        $response = $this->get('/icons/example.com/icon.png')->assertStatus(200)->assertHeader('Content-Type', 'image/png')
            ->assertHeader('Cache-Control', 'immutable, max-age=2592000, public')->assertHeader('Expires')
            ->assertHeaderMissing('Cross-Origin-Resource-Policy');
        $this->assertSame(self::PNG.'best', $response->getContent());
        // The page is the Referer for the icon.
        $this->assertSame([['https://example.com', ''], ['https://example.com/best.png', 'https://example.com/']], $this->sites->requests);
        $this->assertSame(self::PNG.'best', file_get_contents("{$this->cache}/example.com.png"));

        // From the cache, until ICON_CACHE_TTL has passed.
        $this->sites->answer('https://example.com/best.png', self::PNG.'new');
        $this->assertSame(self::PNG.'best', $this->get('/icons/example.com/icon.png')->getContent());
        $this->assertCount(2, $this->sites->requests);

        touch("{$this->cache}/example.com.png", time() - 2_592_000);
        $this->assertSame(self::PNG.'new', $this->get('/icons/example.com/icon.png')->getContent());
        $this->assertCount(4, $this->sites->requests);
    }

    public function test_failures_are_remembered(): void
    {
        $fallback = file_get_contents(resource_path('vaultwarden/static/images/fallback-icon.png'));

        $response = $this->get('/icons/example.com/icon.png')->assertStatus(200)->assertHeader('Content-Type', 'image/png')
            ->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        $this->assertSame($fallback, $response->getContent());
        // HTTPS, HTTP, then with www. in front; then the default locations, the last failure counts.
        $this->assertSame([
            'https://example.com', 'http://example.com', 'https://www.example.com', 'http://www.example.com',
            'https://example.com/favicon.ico', 'http://example.com/favicon.ico', 'https://example.com/apple-touch-icon.png',
            'http://example.com/apple-touch-icon.png',
        ], array_column($this->sites->requests, 0));
        $this->assertFileExists("{$this->cache}/example.com.png.miss");

        // Not tried again until ICON_CACHE_NEGTTL has passed; then the marker goes.
        $this->sites->answer('https://example.com', '')->answer('https://example.com/favicon.ico', "\0\0\1\0\1\0");
        $this->assertSame($fallback, $this->get('/icons/example.com/icon.png')->getContent());
        $this->assertCount(8, $this->sites->requests);

        touch("{$this->cache}/example.com.png.miss", time() - 259_200);
        $this->get('/icons/example.com/icon.png')->assertHeader('Content-Type', 'image/x-icon');
        $this->assertFileDoesNotExist("{$this->cache}/example.com.png.miss");
    }

    #[Parity('config:ICON_DOWNLOAD_TIMEOUT')]
    public function test_one_deadline_for_the_whole_download(): void
    {
        // Eight requests of 0.6 s each would hold a worker for 4.8 s; the download ends after 2 s.
        $this->changeVaultwardenEnvironment(['ICON_DOWNLOAD_TIMEOUT' => '1']);
        $this->sites->delay = 600_000;

        $start = microtime(true);
        $this->get('/icons/example.com/icon.png')->assertStatus(200)->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        $this->assertLessThan(3.0, microtime(true) - $start);
        $this->assertLessThan(8, count($this->sites->requests));
        // Remembered like any failure, so the next request costs nothing.
        $this->assertFileExists("{$this->cache}/example.com.png.miss");
    }

    public function test_other_ways_to_the_page(): void
    {
        // HTTP when HTTPS fails, and after redirects the icons are relative to the last URL.
        $this->sites->answer('http://example.com', '<link rel=icon href=icon.gif>', finalUrl: 'http://example.com/home/')
            ->answer('http://example.com/home/icon.gif', 'GIF89a');
        $this->get('/icons/example.com/icon.png')->assertHeader('Content-Type', 'image/gif');

        // Without subdomains when both fail.
        $this->sites->answer('https://example.net', '<link rel=icon href=/net.png>')->answer('https://example.net/net.png', self::PNG);
        $this->get('/icons/a.b.example.net/icon.png')->assertHeader('Content-Type', 'image/png');
        $this->assertContains(['https://example.net/net.png', 'https://example.net/'], $this->sites->requests);
    }

    public function test_only_the_five_best_candidates(): void
    {
        $this->sites->answer('https://example.com', '<link rel=icon href=1.html sizes=32x32><link rel=icon href=2.html sizes=64x64>'
            .'<link rel=icon href=3.html sizes=24x24><link rel=icon href=4.png><link rel=icon href=5.jpg><link rel=icon href=6.png sizes=16x16>');
        foreach (['1.html', '2.html', '3.html', '6.png'] as $file) {
            $this->sites->answer("https://example.com/{$file}", '<html>');
        }
        $this->sites->answer('https://example.com/4.png', 'not a png')->answer('https://example.com/5.jpg', "\xFF\xD8\xFF\xE0");

        $this->get('/icons/example.com/icon.png')->assertHeader('Content-Type', 'image/png')
            ->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        $this->assertNotContains('https://example.com/5.jpg', array_column($this->sites->requests, 0));
    }

    public function test_icons_in_data_urls(): void
    {
        $icon = self::PNG.str_repeat('x', 59);
        $this->sites->answer('https://example.com', '<link rel=icon sizes=32x32 href="data:image/png;base64,'.base64_encode(self::PNG).'">'
            .'<link rel=icon sizes=64x64 href="data:image/png;base64,'.base64_encode($icon).'">');

        $this->assertSame($icon, $this->get('/icons/example.com/icon.png')->assertHeader('Content-Type', 'image/png')->getContent());
        $this->assertCount(1, $this->sites->requests);
    }

    public function test_svg_icons_are_filtered(): void
    {
        $this->sites->answer('https://example.com', '<link rel=icon href=/a.svg><link rel=icon href=/b.svg sizes=32x32>')
            ->answer('https://example.com/a.svg', '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(1)</script><path d="M0"/></svg>')
            ->answer('https://example.com/b.svg', '<svg xmlns="http://www.w3.org/2000/svg"><path></svg>');

        // A broken SVG is an empty icon without a type, and is cached as such.
        $broken = $this->get('/icons/example.com/icon.png')->assertHeader('Content-Type', 'image/x-icon')
            ->assertHeader('Cache-Control', 'immutable, max-age=2592000, public');
        $this->assertSame('', $broken->getContent());
        $this->assertSame('', file_get_contents("{$this->cache}/example.com.png"));

        $this->sites->answer('https://example.org', '<link rel=icon href=/a.svg>')
            ->answer('https://example.org/a.svg', '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(1)</script><path d="M0"/></svg>');
        $this->assertSame("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\">\n  <path d=\"M0\"/>\n</svg>",
            $this->get('/icons/example.org/icon.png')->assertHeader('Content-Type', 'image/svg+xml')->getContent());
        // From the cache, the type comes from the bytes.
        $this->get('/icons/example.org/icon.png')->assertHeader('Content-Type', 'image/svg+xml');
    }

    public function test_large_icons_are_cut(): void
    {
        $this->sites->answer('https://example.com', '<link rel=icon href=/big.png>')
            ->answer('https://example.com/big.png', self::PNG.str_repeat('x', 6 * 1024 * 1024));

        $this->assertSame(5120 * 1024, strlen((string) $this->get('/icons/example.com/icon.png')->getContent()));
    }

    #[Parity('config:HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS')]
    #[Parity('config:HTTP_REQUEST_BLOCK_REGEX')]
    public function test_blocked_hosts(): void
    {
        // Before any request, and without a miss file that would reveal them.
        $this->get('/icons/127.0.0.1/icon.png')->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        $this->get('/icons/2130706433/icon.png')->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        $this->assertSame([], $this->sites->requests);

        $this->sites->answer('https://example.com', '<link rel=icon href=https://10.0.0.1/a.png sizes=32x32><link rel=icon href=/b.png>')
            ->answer('https://example.com/b.png', self::PNG);
        $this->get('/icons/example.com/icon.png')->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        $this->assertNotContains('https://example.com/b.png', array_column($this->sites->requests, 0));
        $this->assertFileDoesNotExist("{$this->cache}/example.com.png.miss");

        $this->sites->fail('https://example.org', new BlockedHost('Blocked domain'));
        $this->get('/icons/example.org/icon.png')->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        // A blocked page is not retried over HTTP.
        $this->assertNotContains('http://example.org', array_column($this->sites->requests, 0));

        $this->changeVaultwardenEnvironment(['HTTP_REQUEST_BLOCK_REGEX' => '^example\.net$']);
        $this->get('/icons/example.net/icon.png')->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        $this->assertNotContains('https://example.net', array_column($this->sites->requests, 0));
    }

    public function test_invalid_hosts(): void
    {
        $this->get('/icons/dead_beaf.cafe/icon.png')->assertStatus(200)->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        $this->get('/icons/example.com%3A443/icon.png')->assertStatus(200)->assertHeader('Cache-Control', 'immutable, max-age=259200, public');
        $this->assertSame([], $this->sites->requests);
    }

    public function test_icon_downloads_can_be_disabled(): void
    {
        mkdir($this->cache);
        file_put_contents("{$this->cache}/example.com.png", 'GIF89a');
        $this->changeVaultwardenEnvironment(['DISABLE_ICON_DOWNLOAD' => 'true', 'ICON_CACHE_TTL' => '0', 'ICON_CACHE_NEGTTL' => '60']);

        // Cached icons stay, with ICON_CACHE_TTL 0 for ever.
        touch("{$this->cache}/example.com.png", time() - 100_000_000);
        $this->get('/icons/example.com/icon.png')->assertHeader('Content-Type', 'image/gif')->assertHeader('Cache-Control', 'immutable, max-age=0, public');
        $this->get('/icons/example.org/icon.png')->assertHeader('Content-Type', 'image/png')->assertHeader('Cache-Control', 'immutable, max-age=60, public');
        $this->assertSame([], $this->sites->requests);
        $this->assertFileDoesNotExist("{$this->cache}/example.org.png.miss");
    }
}
