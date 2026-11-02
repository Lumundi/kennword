<?php

namespace App\Parity\Watch\Sources;

use App\Parity\Matrix;
use App\Parity\Reference;
use App\Parity\Watch\Finding;
use App\Parity\Watch\Source;
use Illuminate\Support\Facades\Http;

/**
 * Advisories (RustSec, via OSV) for the crates whose behaviour Kennword
 * reproduces, in the versions of the pinned Cargo.lock. We do not run their
 * code, but a flaw in their logic is likely ported along.
 */
final readonly class RustCrates implements Source
{
    /**
     * The crates NOTICE.md names under Rocket and "Other Rust crates", with the
     * crates they come with; a test keeps the list complete.
     */
    public const array CRATES = [
        'rocket', 'rocket_http', 'rocket_ws', 'tungstenite', 'diesel', 'serde', 'serde_json', 'chrono',
        'jsonwebtoken', 'governor', 'data-encoding', 'openidconnect', 'oauth2', 'rsa', 'p256', 'p384', 'url', 'lettre', 'handlebars',
        'webauthn-rs', 'webauthn-rs-core', 'webauthn-rs-proto', 'base64urlsafedata', 'serde_cbor_2', 'yubico_ng',
        'cron', 'job_scheduler_ng', 'reqwest', 'rustls-native-certs', 'cookie_store', 'rmp', 'rmpv', 'grass_compiler',
    ];

    public const string API = 'https://api.osv.dev/v1';

    public function __construct(
        private Reference $reference,
    ) {}

    public function name(): string
    {
        return 'osv';
    }

    public function findings(): array
    {
        $this->reference->assertCheckedOut();
        $locked = self::lockedVersions((string) file_get_contents($this->reference->checkout.'/Cargo.lock'));

        $queries = [];
        foreach (self::CRATES as $crate) {
            foreach ($locked[$crate] ?? [] as $version) {
                $queries[] = ['package' => ['ecosystem' => 'crates.io', 'name' => $crate], 'version' => $version];
            }
        }

        $results = Http::timeout(30)->post(self::API.'/querybatch', ['queries' => $queries])->throw()->json('results');
        $found = [];

        foreach (is_array($results) ? $results : [] as $index => $result) {
            foreach (is_array($result) && is_array($result['vulns'] ?? null) ? $result['vulns'] : [] as $vulnerability) {
                $id = is_array($vulnerability) ? Matrix::string($vulnerability['id'] ?? '') : '';
                if ($id !== '' && isset($queries[$index])) {
                    $found[$id] ??= $queries[$index];
                }
            }
        }

        // OSV lists a flaw once per database (RUSTSEC-…, GHSA-…), linked as aliases. Report it
        // once, under RustSec's id, and not at all when RustSec calls it informational.
        uksort($found, static fn (string $a, string $b): int => [! str_starts_with($a, 'RUSTSEC-'), $a] <=> [! str_starts_with($b, 'RUSTSEC-'), $b]);
        $seen = [];
        $findings = [];

        foreach ($found as $id => $query) {
            if (in_array($id, $seen, true)) {
                continue;
            }

            $details = Http::timeout(30)->get(self::API."/vulns/{$id}")->throw()->json();
            $aliases = is_array($details) && is_array($details['aliases'] ?? null) ? array_map(Matrix::string(...), $details['aliases']) : [];
            if (! is_array($details) || array_intersect([$id, ...$aliases], $seen) !== []) {
                continue;
            }

            $seen = [...$seen, $id, ...$aliases];
            if (! self::informational($details)) {
                $findings[] = $this->finding($id, $query['package']['name'], $query['version'], $details);
            }
        }

        return $findings;
    }

    /**
     * @param  array<mixed>  $details
     */
    private function finding(string $id, string $crate, string $version, array $details): Finding
    {
        $aliases = is_array($details['aliases'] ?? null) ? array_map(Matrix::string(...), $details['aliases']) : [];

        return new Finding(
            key: "osv:{$id}",
            title: mb_strimwidth(sprintf('%s in %s %s: %s', $id, $crate, $version, Matrix::string($details['summary'] ?? '')), 0, 250, '…'),
            body: sprintf(
                "OSV reports [%s](https://osv.dev/vulnerability/%s)%s for `%s` %s, the version in the pinned commit's `Cargo.lock`.\n\n"
                ."Kennword does not run this crate, but it reproduces its behaviour (NOTICE.md).\n\n"
                ."- [ ] Check whether the flaw is in behaviour we reproduce (for example how tokens are checked) or only in the Rust code (memory safety, panics).\n"
                .'- [ ] If we reproduce it, follow SECURITY.md, and watch for Vaultwarden updating the crate.',
                $id, $id, $aliases === [] ? '' : ' ('.implode(', ', $aliases).')', $crate, $version,
            ),
            labels: ['security', 'upstream'],
        );
    }

    /**
     * RustSec's informational advisories (unmaintained, unsound) are about the
     * Rust code, not the behaviour we reproduce.
     *
     * @param  array<mixed>  $details
     */
    private static function informational(array $details): bool
    {
        $specific = [$details['database_specific'] ?? null];
        foreach (is_array($details['affected'] ?? null) ? $details['affected'] : [] as $affected) {
            $specific[] = is_array($affected) ? ($affected['database_specific'] ?? null) : null;
        }

        foreach ($specific as $data) {
            if (is_array($data) && ($data['informational'] ?? null) !== null) {
                return true;
            }
        }

        return false;
    }

    /**
     * The versions of each package in a Cargo.lock.
     *
     * @return array<string, list<string>>
     */
    public static function lockedVersions(string $lock): array
    {
        preg_match_all('/^\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"/m', $lock, $matches, PREG_SET_ORDER);
        $versions = [];
        foreach ($matches as [, $name, $version]) {
            $versions[$name][] = $version;
        }

        return $versions;
    }
}
