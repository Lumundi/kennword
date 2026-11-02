<?php

namespace App\Parity\Watch\Sources;

use App\Parity\Matrix;
use App\Parity\Reference;
use App\Parity\Upstream\Counterparts;
use App\Parity\Watch\Finding;
use App\Parity\Watch\GitHub;
use App\Parity\Watch\Source;
use App\Support\SemVer;
use Illuminate\Support\Str;

/**
 * Advisories Vaultwarden publishes. Each one asks whether our port has the
 * flaw too, whether or not the pin already contains the fix: the port may
 * have been written before, or may not follow the fix exactly.
 */
final readonly class VaultwardenAdvisories implements Source
{
    /**
     * The advisories published before the watch started are a backlog of their
     * own (docs/maintenance.md), not one issue each.
     */
    public const string SINCE = '2026-10-29T00:00:00Z';

    public function __construct(
        private GitHub $github,
        private Reference $reference,
        private Counterparts $counterparts,
    ) {}

    public function name(): string
    {
        return 'vaultwarden-advisory';
    }

    public function findings(): array
    {
        $repository = Str::after($this->reference->webUrl(), 'https://github.com/');
        $advisories = $this->github->get("/repos/{$repository}/security-advisories", [
            'per_page' => 100, 'sort' => 'published', 'direction' => 'desc',
        ]);
        $findings = [];

        foreach (is_array($advisories) ? $advisories : [] as $advisory) {
            if (is_array($advisory) && strcmp(Matrix::string($advisory['published_at'] ?? ''), self::SINCE) >= 0) {
                $findings[] = $this->finding($advisory);
            }
        }

        return $findings;
    }

    /**
     * @param  array<mixed>  $advisory
     */
    private function finding(array $advisory): Finding
    {
        $id = Matrix::string($advisory['ghsa_id'] ?? '');
        $severity = Matrix::string($advisory['severity'] ?? '') ?: 'unknown';
        $cvss = is_array($advisory['cvss'] ?? null) ? Matrix::string($advisory['cvss']['score'] ?? '') : '';

        $affected = [];
        $patched = [];
        foreach (is_array($advisory['vulnerabilities'] ?? null) ? $advisory['vulnerabilities'] : [] as $vulnerability) {
            if (is_array($vulnerability)) {
                $affected[] = Matrix::string($vulnerability['vulnerable_version_range'] ?? '');
                $patched[] = Matrix::string($vulnerability['patched_versions'] ?? '');
            }
        }
        $patched = array_values(array_filter($patched));

        $weaknesses = [];
        foreach (is_array($advisory['cwes'] ?? null) ? $advisory['cwes'] : [] as $cwe) {
            $weaknesses[] = is_array($cwe) ? Matrix::string($cwe['cwe_id'] ?? '') : '';
        }

        $rows = [
            'Severity' => $severity.($cvss === '' ? '' : " (CVSS {$cvss})"),
            'Weaknesses' => implode(', ', array_filter($weaknesses)) ?: 'not given',
            'Affected' => implode(', ', array_filter($affected)) ?: 'not given',
            'Fixed in' => $patched === [] ? 'no release yet' : implode(', ', $patched),
            "In the pin ({$this->reference->release})" => $this->inPin($patched),
        ];

        return new Finding(
            key: "vaultwarden-advisory:{$id}",
            title: mb_strimwidth(sprintf('%s (%s): %s', $id, $severity, Matrix::string($advisory['summary'] ?? '')), 0, 250, '…'),
            body: sprintf("Vaultwarden published [%s](%s) on %s.\n\n", $id, Matrix::string($advisory['html_url'] ?? ''), substr(Matrix::string($advisory['published_at'] ?? ''), 0, 10))
                ."| | |\n| --- | --- |\n"
                .implode("\n", array_map(static fn (string $name, string $value): string => "| {$name} | {$value} |", array_keys($rows), $rows))
                .$this->source(Matrix::string($advisory['description'] ?? ''))
                ."\n\n- [ ] Check whether Kennword has the flaw: compare our counterpart with Vaultwarden's fix.\n"
                ."- [ ] If it has, do not discuss the details here: fix it privately as SECURITY.md describes, then close this issue.\n"
                .'- [ ] Add a regression test, so that the fix cannot get lost when the pin moves.',
            labels: ['upstream-security'],
        );
    }

    /**
     * @param  list<string>  $patched
     */
    private function inPin(array $patched): string
    {
        $pinned = SemVer::parse($this->reference->release);
        $fixed = preg_match('/\d+\.\d+\.\d+/', $patched[0] ?? '', $match) === 1 ? SemVer::parse($match[0]) : null;

        if ($pinned === null || $fixed === null) {
            return 'unknown';
        }

        return SemVer::compare($pinned, $fixed) >= 0
            ? 'yes; check that the port follows the fix'
            : '**no**; port the fix and move the pin';
    }

    /**
     * The Rust files and functions the description names, with our counterparts.
     */
    private function source(string $description): string
    {
        preg_match_all('#\bsrc/[\w/]+\.rs\b#', $description, $files);
        preg_match_all('/`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?:\(\))?`/', $description, $functions);
        $functions = array_values(array_unique($functions[1]));
        if ($functions === [] && $files[0] === []) {
            return '';
        }

        $rows = [];
        foreach ($functions as $function) {
            $items = $this->counterparts->handlers($function);
            $php = $this->counterparts->php($function);
            $rows[] = sprintf(
                '| `%s` | %s | %s |',
                $function,
                $items === [] ? '' : implode('<br>', array_map(static fn (string $id): string => "`{$id}`", $items)),
                $php === [] ? 'not found by name' : implode('<br>', array_map(static fn (string $place): string => "`{$place}`", array_slice($php, 0, 3))),
            );
        }

        $files = array_values(array_unique($files[0]));

        return "\n\nThe advisory names "
            .($files === [] ? 'these functions' : implode(', ', array_map(static fn (string $file): string => "`{$file}`", $files)).($rows === [] ? '' : ' and these functions'))
            .'.'.($rows === [] ? '' : "\n\n| Function | Parity items | Our counterpart |\n| --- | --- | --- |\n".implode("\n", $rows));
    }
}
