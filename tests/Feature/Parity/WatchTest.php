<?php

namespace Tests\Feature\Parity;

use App\Parity\Reference;
use App\Parity\Upstream\Counterparts;
use App\Parity\Watch\Finding;
use App\Parity\Watch\GitHub;
use App\Parity\Watch\Issues;
use App\Parity\Watch\Sources\ComposerAudit;
use App\Parity\Watch\Sources\ComposerUpdates;
use App\Parity\Watch\Sources\PhpReleases;
use App\Parity\Watch\Sources\RustCrates;
use App\Parity\Watch\Sources\VaultwardenAdvisories;
use App\Parity\Watch\Sources\VaultwardenReleases;
use App\Parity\Watch\Sources\WebVaultReleases;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Str;
use RuntimeException;
use Tests\TestCase;

class WatchTest extends TestCase
{
    private const string PIN = '0f44744ef86a2a7bea615af1c024044ce5736187';

    protected function setUp(): void
    {
        parent::setUp();

        Http::preventStrayRequests();
    }

    public function test_composer_audit_reports_advisories_and_abandoned_packages(): void
    {
        File::put($this->dataFolder.'/composer.lock', json_encode([
            'packages' => [['name' => 'symfony/mime', 'version' => 'v7.3.4']],
            'packages-dev' => [['name' => 'old/thing', 'version' => '1.0.0']],
        ], JSON_THROW_ON_ERROR));
        Process::fake(['*composer*audit*' => Process::result(output: json_encode([
            'advisories' => ['symfony/mime' => [[
                'advisoryId' => 'PKSA-1234-abcd',
                'packageName' => 'symfony/mime',
                'affectedVersions' => '>=7.0,<7.3.5',
                'title' => 'Header injection',
                'cve' => 'CVE-2026-45070',
                'link' => 'https://symfony.com/cve-2026-45070',
                'reportedAt' => '2026-10-27T00:00:00+00:00',
                'sources' => [['name' => 'GitHub', 'remoteId' => 'GHSA-aaaa-bbbb-cccc']],
                'severity' => 'medium',
            ]]],
            'abandoned' => ['old/thing' => 'new/thing'],
        ], JSON_THROW_ON_ERROR), exitCode: 3)]);

        [$advisory, $abandoned] = new ComposerAudit($this->dataFolder)->findings();

        $this->assertSame('composer-audit:PKSA-1234-abcd', $advisory->key);
        $this->assertSame('CVE-2026-45070 in symfony/mime v7.3.4: Header injection', $advisory->title);
        $this->assertSame(['security', 'dependencies'], $advisory->labels);
        $this->assertTrue($advisory->resolvable);
        $this->assertStringContainsString("| Affected versions | `>=7.0,<7.3.5` |\n| Severity | medium |\n| Advisory | [PKSA-1234-abcd](https://symfony.com/cve-2026-45070) |", $advisory->body);
        $this->assertStringContainsString('| Sources | GHSA-aaaa-bbbb-cccc (GitHub) |', $advisory->body);

        $this->assertSame('composer-audit:abandoned:old/thing', $abandoned->key);
        $this->assertStringContainsString('its authors suggest `new/thing`', $abandoned->body);
    }

    public function test_composer_audit_fails_without_an_answer(): void
    {
        Process::fake(['*' => Process::result(output: 'not json', errorOutput: 'Could not open composer.lock', exitCode: 1)]);

        $this->expectExceptionObject(new RuntimeException('composer audit failed: Could not open composer.lock'));
        new ComposerAudit($this->dataFolder)->findings();
    }

    public function test_composer_updates_lists_minor_and_major_updates_in_one_issue(): void
    {
        Process::fake(['*composer*outdated*' => json_encode(['locked' => [
            ['name' => 'laravel/framework', 'version' => 'v13.38.0', 'latest' => 'v13.39.0'],
            ['name' => 'phpunit/phpunit', 'version' => '12.5.42', 'latest' => '13.4.5'],
            ['name' => 'laravel/pint', 'version' => 'v1.27.0', 'latest' => 'v1.27.1'],
        ]], JSON_THROW_ON_ERROR)]);

        [$finding] = new ComposerUpdates($this->dataFolder)->findings();

        $this->assertSame('composer-updates:direct', $finding->key);
        $this->assertSame('Composer: 2 minor or major updates are available', $finding->title);
        $this->assertStringContainsString("| `laravel/framework` | v13.38.0 | v13.39.0 | minor |\n| `phpunit/phpunit` | 12.5.42 | 13.4.5 | major |\n\n", $finding->body);
        $this->assertTrue($finding->resolvable);
        $this->assertNull(ComposerUpdates::kind('dev-main', 'v1.0.0'));
    }

    public function test_composer_updates_reports_nothing_when_only_patches_are_left(): void
    {
        Process::fake(['*' => json_encode(['locked' => [['name' => 'laravel/pint', 'version' => 'v1.27.0', 'latest' => 'v1.27.1']]], JSON_THROW_ON_ERROR)]);

        $this->assertSame([], new ComposerUpdates($this->dataFolder)->findings());
    }

    public function test_vaultwarden_releases_after_the_pin_are_reported_with_their_advisories(): void
    {
        Http::fake(['api.github.com/repos/dani-garcia/vaultwarden/releases*' => Http::response([
            ['tag_name' => '1.38.0', 'html_url' => 'https://github.com/dani-garcia/vaultwarden/releases/tag/1.38.0', 'published_at' => '2026-11-02T10:00:00Z', 'body' => "## Security Fixes\n- Sends [[GHSA-69q9-v8p6-xvx3]](https://example) (**High**, 8.1)\n- Login [GHSA-7jg8-8m5x-6j9r]\n\n## What's Changed\n* Something by @someone"],
            ['tag_name' => '1.37.5', 'html_url' => 'https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.5', 'published_at' => '2026-10-30T10:00:00Z', 'body' => "## What's Changed\n* Fix a typo"],
            ['tag_name' => '1.37.4', 'published_at' => '2026-10-05T23:40:54Z', 'body' => '## Security Fixes'],
            ['tag_name' => '1.39.0', 'draft' => true, 'body' => ''],
        ])]);

        [$security, $plain] = new VaultwardenReleases(new GitHub('token'), $this->reference())->findings();

        $this->assertSame('vaultwarden-release:1.38.0', $security->key);
        $this->assertSame('Vaultwarden 1.38.0 is released with security fixes', $security->title);
        $this->assertSame(['upstream', 'upstream-security'], $security->labels);
        $this->assertStringContainsString("- [GHSA-69q9-v8p6-xvx3](https://github.com/dani-garcia/vaultwarden/security/advisories/GHSA-69q9-v8p6-xvx3) (High)\n- [GHSA-7jg8-8m5x-6j9r](https://github.com/dani-garcia/vaultwarden/security/advisories/GHSA-7jg8-8m5x-6j9r)\n", $security->body);
        $this->assertStringNotContainsString('someone', $security->body);
        $this->assertTrue($security->resolvable);

        $this->assertSame('Vaultwarden 1.37.5 is released', $plain->title);
        $this->assertSame(['upstream'], $plain->labels);
        $this->assertStringNotContainsString('Its notes name security fixes', $plain->body);

        Http::assertSent(static fn (Request $request): bool => $request->hasHeader('Authorization', 'Bearer token'));
    }

    public function test_vaultwarden_advisories_since_the_watch_started_ask_for_a_check_of_our_port(): void
    {
        File::ensureDirectoryExists($this->dataFolder.'/app');
        File::put($this->dataFolder.'/app/Controller.php', "<?php\n\nfunction putCipherShare() {}\n");
        $counterparts = new Counterparts([
            'route:PUT /api/ciphers/{cipher_id}/share' => ['handler' => 'core::ciphers::put_cipher_share', 'source' => 'src/api/core/ciphers.rs:10'],
        ], $this->dataFolder);

        Http::fake(['api.github.com/repos/dani-garcia/vaultwarden/security-advisories*' => Http::response([
            [
                'ghsa_id' => 'GHSA-aaaa-bbbb-cccc', 'html_url' => 'https://github.com/dani-garcia/vaultwarden/security/advisories/GHSA-aaaa-bbbb-cccc',
                'summary' => 'Sharing | moves items', 'severity' => 'high', 'cvss' => ['score' => 8.1],
                'cwes' => [['cwe_id' => 'CWE-863']], 'published_at' => '2026-11-03T18:00:00Z',
                'vulnerabilities' => [['vulnerable_version_range' => '<= 1.37.3', 'patched_versions' => '1.37.4']],
                'description' => 'In `src/api/core/ciphers.rs`, `put_cipher_share()` calls `update_cipher_from_data` without `Option`.',
            ],
            [
                'ghsa_id' => 'GHSA-dddd-eeee-ffff', 'summary' => 'Newer', 'severity' => 'medium', 'published_at' => '2026-11-04T18:00:00Z',
                'vulnerabilities' => [['vulnerable_version_range' => '<= 1.38.0', 'patched_versions' => '1.38.1']], 'description' => '',
            ],
            ['ghsa_id' => 'GHSA-gggg-hhhh-jjjj', 'published_at' => '2026-10-28T18:01:28Z', 'vulnerabilities' => []],
        ])]);

        [$fixed, $open] = new VaultwardenAdvisories(new GitHub(null), $this->reference(), $counterparts)->findings();

        $this->assertSame('vaultwarden-advisory:GHSA-aaaa-bbbb-cccc', $fixed->key);
        $this->assertSame('GHSA-aaaa-bbbb-cccc (high): Sharing | moves items', $fixed->title);
        $this->assertSame(['upstream-security'], $fixed->labels);
        $this->assertFalse($fixed->resolvable);
        $this->assertStringContainsString("| Severity | high (CVSS 8.1) |\n| Weaknesses | CWE-863 |\n| Affected | <= 1.37.3 |\n| Fixed in | 1.37.4 |\n| In the pin (1.37.4) | yes; check that the port follows the fix |", $fixed->body);
        $this->assertStringContainsString("The advisory names `src/api/core/ciphers.rs` and these functions.\n\n| Function | Parity items | Our counterpart |\n| --- | --- | --- |\n"
            ."| `put_cipher_share` | `route:PUT /api/ciphers/{cipher_id}/share` | `app/Controller.php:3` |\n| `update_cipher_from_data` |  | not found by name |", $fixed->body);

        $this->assertStringContainsString('| In the pin (1.37.4) | **no**; port the fix and move the pin |', $open->body);
        $this->assertStringNotContainsString('The advisory names', $open->body);
    }

    public function test_a_newer_web_vault_says_whether_vaultwarden_ships_it(): void
    {
        Http::fake([
            'api.github.com/repos/dani-garcia/bw_web_builds/releases*' => Http::response([
                ['tag_name' => 'v2026.10.0', 'prerelease' => true],
                ['tag_name' => 'v2026.9.1', 'html_url' => 'https://github.com/dani-garcia/bw_web_builds/releases/tag/v2026.9.1', 'published_at' => '2026-11-01T00:00:00Z'],
                ['tag_name' => 'v2026.9.0'],
                ['tag_name' => 'v2026.8.0'],
            ]),
            'api.github.com/repos/dani-garcia/vaultwarden/contents/docker/DockerSettings.yaml' => Http::response([
                'content' => base64_encode("vault_version: \"v2026.9.1\"\nvault_image_digest: \"sha256:1\"\n"),
            ]),
        ]);

        [$finding] = new WebVaultReleases(new GitHub(null), $this->reference())->findings();

        $this->assertSame('web-vault:2026.8.0', $finding->key);
        $this->assertSame('Web vault v2026.9.1 is out; the pin ships 2026.8.0', $finding->title);
        $this->assertStringContainsString('Vaultwarden `main` ships it already', $finding->body);
        $this->assertTrue($finding->resolvable);
    }

    public function test_php_security_releases_of_the_required_branch_and_the_newest_are_reported_once(): void
    {
        File::put($this->dataFolder.'/composer.json', '{"require": {"php": "^8.5"}}');
        Http::fake([
            'www.php.net/releases/index.php?json=&version=8.5' => Http::response(['version' => '8.5.12', 'date' => '21 Oct 2026', 'tags' => ['security']]),
            'www.php.net/releases/index.php?json=&version=8' => Http::response(['version' => '8.5.12', 'date' => '21 Oct 2026', 'tags' => ['security']]),
        ]);

        [$finding] = new PhpReleases($this->dataFolder)->findings();
        $this->assertSame('php:8.5.12', $finding->key);
        $this->assertSame('PHP 8.5.12 is a security release', $finding->title);
        $this->assertStringContainsString('PHP [8.5.12](https://www.php.net/ChangeLog-8.php#8.5.12) of 21 Oct 2026', $finding->body);
    }

    public function test_a_newer_php_branch_counts_too(): void
    {
        File::put($this->dataFolder.'/composer.json', '{"require": {"php": "^8.5"}}');
        Http::fake([
            'www.php.net/releases/index.php?json=&version=8.5' => Http::response(['version' => '8.5.13', 'tags' => []]),
            'www.php.net/releases/index.php?json=&version=8' => Http::response(['version' => '8.6.1', 'date' => '5 Nov 2026', 'tags' => ['security']]),
        ]);
        $this->assertSame(['php:8.6.1'], array_map(static fn (Finding $finding): string => $finding->key, new PhpReleases($this->dataFolder)->findings()));
    }

    public function test_crate_advisories_are_reported_once_and_not_when_informational(): void
    {
        $checkout = $this->dataFolder.'/checkout';
        File::ensureDirectoryExists($checkout.'/.git');
        File::put($checkout.'/.git/HEAD', self::PIN."\n");
        File::put($checkout.'/Cargo.lock', "[[package]]\nname = \"jsonwebtoken\"\nversion = \"11.1.0\"\n\n[[package]]\nname = \"url\"\nversion = \"2.5.8\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.0.0\"\n");
        $this->assertSame(['jsonwebtoken' => ['11.1.0'], 'url' => ['2.5.8'], 'tokio' => ['1.0.0']], RustCrates::lockedVersions((string) File::get($checkout.'/Cargo.lock')));

        Http::fake([
            'api.osv.dev/v1/querybatch' => Http::response(['results' => [
                ['vulns' => [['id' => 'GHSA-1111-2222-3333'], ['id' => 'RUSTSEC-2026-0001']]],
                ['vulns' => [['id' => 'RUSTSEC-2026-0002'], ['id' => 'GHSA-4444-5555-6666']]],
            ]]),
            'api.osv.dev/v1/vulns/RUSTSEC-2026-0001' => Http::response(['id' => 'RUSTSEC-2026-0001', 'summary' => 'Tokens accepted without exp', 'aliases' => ['GHSA-1111-2222-3333', 'CVE-2026-1']]),
            'api.osv.dev/v1/vulns/GHSA-1111-2222-3333' => Http::response(['id' => 'GHSA-1111-2222-3333', 'aliases' => ['RUSTSEC-2026-0001']]),
            'api.osv.dev/v1/vulns/RUSTSEC-2026-0002' => Http::response(['id' => 'RUSTSEC-2026-0002', 'aliases' => ['GHSA-4444-5555-6666'], 'affected' => [['database_specific' => ['informational' => 'unsound']]]]),
            'api.osv.dev/v1/vulns/GHSA-4444-5555-6666' => Http::response(['id' => 'GHSA-4444-5555-6666', 'aliases' => ['RUSTSEC-2026-0002']]),
        ]);

        [$finding] = new RustCrates($this->reference($checkout))->findings();

        $this->assertSame('osv:RUSTSEC-2026-0001', $finding->key);
        $this->assertSame('RUSTSEC-2026-0001 in jsonwebtoken 11.1.0: Tokens accepted without exp', $finding->title);
        $this->assertStringContainsString('(GHSA-1111-2222-3333, CVE-2026-1) for `jsonwebtoken` 11.1.0', $finding->body);
        Http::assertSent(static fn (Request $request): bool => $request->url() === 'https://api.osv.dev/v1/querybatch' && $request['queries'] === [
            ['package' => ['ecosystem' => 'crates.io', 'name' => 'jsonwebtoken'], 'version' => '11.1.0'],
            ['package' => ['ecosystem' => 'crates.io', 'name' => 'url'], 'version' => '2.5.8'],
        ]);
    }

    public function test_the_watched_crates_include_every_crate_notice_names(): void
    {
        $section = Str::between((string) File::get(base_path('NOTICE.md')), "\n## Other Rust crates\n", "\n## ");
        preg_match_all('/^\| (.+?) \|/m', $section, $columns);
        preg_match_all('/\[([^\]]+)\]\(/', implode("\n", $columns[1]), $names);
        $names = array_diff(array_map(strtolower(...), $names[1]), ['rust standard library']);
        $this->assertContains('jsonwebtoken', $names);

        foreach ($names as $name) {
            $this->assertContains(['handlebars-rust' => 'handlebars', 'grass' => 'grass_compiler'][$name] ?? $name, RustCrates::CRATES);
        }
    }

    public function test_issues_follow_the_findings(): void
    {
        $marker = static fn (string $key, bool $resolvable = false): string => "\n\n<!-- parity:watch {$key}".($resolvable ? ' resolvable' : '').' -->';
        $requests = [];
        Http::fake(function (Request $request) use (&$requests, $marker) {
            $requests[] = [$request->method(), str_replace('https://api.github.com', '', $request->url()), $request->data()];

            return match (true) {
                str_contains($request->url(), '/labels') && $request->method() === 'GET' => Http::response([['name' => 'watch'], ['name' => 'upstream']]),
                str_contains($request->url(), '/issues?') => Http::response([
                    ['number' => 1, 'title' => 'Same', 'state' => 'open', 'labels' => [['name' => 'watch']], 'body' => 'Unchanged'.$marker('php:8.5.12')],
                    ['number' => 2, 'title' => 'Old title', 'state' => 'open', 'labels' => [], 'body' => 'Old'.$marker('vaultwarden-main:0f44744e', true)],
                    ['number' => 3, 'title' => 'Resolved before', 'state' => 'closed', 'labels' => [], 'body' => 'Old'.$marker('composer-audit:PKSA-1', true)],
                    ['number' => 4, 'title' => 'Ignored', 'state' => 'closed', 'labels' => [['name' => 'wontfix']], 'body' => 'Old'.$marker('composer-updates:direct', true)],
                    ['number' => 5, 'title' => 'Done by hand', 'state' => 'closed', 'labels' => [], 'body' => 'Old'.$marker('vaultwarden-advisory:GHSA-1')],
                    ['number' => 6, 'title' => 'Fixed', 'state' => 'open', 'labels' => [], 'body' => 'Old'.$marker('composer-audit:PKSA-2', true)],
                    ['number' => 7, 'title' => 'Not checked', 'state' => 'open', 'labels' => [], 'body' => 'Old'.$marker('osv:RUSTSEC-1', true)],
                    ['number' => 8, 'title' => 'Pull request', 'pull_request' => [], 'body' => 'Old'.$marker('php:8.5.12')],
                ]),
                $request->method() === 'POST' && str_ends_with($request->url(), '/issues') => Http::response(['number' => 9]),
                default => Http::response([]),
            };
        });

        $done = new Issues(new GitHub('token'), 'owner/repo')->sync([
            new Finding('php:8.5.12', 'Same', 'Unchanged', ['security']),
            new Finding('vaultwarden-main:0f44744e', 'New title', 'New', ['upstream'], resolvable: true),
            new Finding('composer-audit:PKSA-1', 'Again', 'Old', ['security'], resolvable: true),
            new Finding('composer-updates:direct', 'Ignored', 'Old', ['dependencies'], resolvable: true),
            new Finding('vaultwarden-advisory:GHSA-1', 'Done by hand', 'New', ['upstream-security']),
            new Finding('vaultwarden-release:1.38.0', 'Vaultwarden 1.38.0 is released', 'Body', ['upstream']),
        ], ['php', 'vaultwarden-main', 'composer-audit', 'composer-updates', 'vaultwarden-advisory', 'vaultwarden-release']);

        $this->assertSame([
            'Updated #2: New title',
            'Reopened #3: Again',
            'Opened #9: Vaultwarden 1.38.0 is released',
            'Closed #6: Fixed',
        ], $done);

        $writes = array_values(array_filter($requests, static fn (array $request): bool => $request[0] !== 'GET'));
        $this->assertEquals([
            ['POST', '/repos/owner/repo/labels', ['name' => 'upstream-security', 'color' => 'b60205', 'description' => 'A security fix in Vaultwarden to port or verify']],
            ['POST', '/repos/owner/repo/labels', ['name' => 'security', 'color' => 'd93f0b', 'description' => 'A security advisory for something Kennword depends on']],
            ['POST', '/repos/owner/repo/labels', ['name' => 'dependencies', 'color' => '0366d6', 'description' => 'Dependency updates']],
            ['PATCH', '/repos/owner/repo/issues/2', ['title' => 'New title', 'body' => 'New'.$marker('vaultwarden-main:0f44744e', true)]],
            ['PATCH', '/repos/owner/repo/issues/3', ['state' => 'open', 'title' => 'Again']],
            ['POST', '/repos/owner/repo/issues', ['title' => 'Vaultwarden 1.38.0 is released', 'body' => 'Body'.$marker('vaultwarden-release:1.38.0'), 'labels' => ['watch', 'upstream']]],
            ['POST', '/repos/owner/repo/issues/6/comments', ['body' => 'The watch no longer reports this, so it is resolved. Closing.']],
            ['PATCH', '/repos/owner/repo/issues/6', ['state' => 'closed', 'state_reason' => 'completed']],
        ], $writes);
    }

    public function test_parity_watch_runs_the_chosen_sources_and_fails_when_one_fails(): void
    {
        Http::fake([
            'www.php.net/*' => Http::response(['version' => '8.5.12', 'date' => '21 Oct 2026', 'tags' => ['security']]),
            'api.github.com/repos/dani-garcia/bw_web_builds/*' => Http::response('', 502),
        ]);

        $this->command('parity:watch', ['--source' => ['php']])
            ->expectsOutputToContain('PHP 8.5.12 is a security release')
            ->assertSuccessful();

        $this->command('parity:watch', ['--source' => ['web-vault']])
            ->expectsOutputToContain('web-vault: HTTP request returned status code 502')
            ->assertFailed();
    }

    private function reference(?string $checkout = null): Reference
    {
        return new Reference(
            repository: 'https://github.com/dani-garcia/vaultwarden.git',
            commit: self::PIN,
            release: '1.37.4',
            webVault: '2026.8.0',
            webVaultDigest: 'sha256:'.str_repeat('0', 64),
            checkout: $checkout ?? $this->dataFolder.'/checkout',
        );
    }
}
