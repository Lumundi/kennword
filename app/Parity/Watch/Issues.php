<?php

namespace App\Parity\Watch;

use App\Parity\Matrix;
use Illuminate\Support\Str;

/**
 * Keeps one GitHub issue per finding. An HTML comment at the end of the body
 * holds the finding's key, so the issues themselves are the watch's memory:
 * new findings open an issue, changed ones update it, and issues of resolvable
 * findings close once their source no longer reports them (and open again if
 * it does, unless they are labelled wontfix). Other closed issues stay closed.
 */
final readonly class Issues
{
    /**
     * The labels the watch uses, with their colours and descriptions.
     */
    public const array LABELS = [
        'watch' => ['ededed', 'Opened by the watch workflow (docs/maintenance.md)'],
        'upstream' => ['1d76db', 'A change in Vaultwarden to port'],
        'upstream-security' => ['b60205', 'A security fix in Vaultwarden to port or verify'],
        'security' => ['d93f0b', 'A security advisory for something Kennword depends on'],
        'dependencies' => ['0366d6', 'Dependency updates'],
    ];

    private const string MARKER = '/<!-- parity:watch (\S+)( resolvable)? -->\s*$/';

    public function __construct(
        private GitHub $github,
        private string $repository,
    ) {}

    /**
     * @param  list<Finding>  $findings
     * @param  list<string>  $sources  The sources that ran without error; only their issues are closed
     * @return list<string> What was done
     */
    public function sync(array $findings, array $sources): array
    {
        $this->ensureLabels();
        $issues = $this->existing();
        $done = [];
        $reported = [];

        foreach ($findings as $finding) {
            $reported[$finding->key] = true;
            $body = sprintf("%s\n\n<!-- parity:watch %s%s -->", $finding->body, $finding->key, $finding->resolvable ? ' resolvable' : '');
            $issue = $issues[$finding->key] ?? null;

            if ($issue === null) {
                $created = $this->github->send('POST', "/repos/{$this->repository}/issues", [
                    'title' => $finding->title,
                    'body' => $body,
                    'labels' => ['watch', ...$finding->labels],
                ]);
                $done[] = sprintf('Opened #%s: %s', Matrix::string($created['number'] ?? '?'), $finding->title);

                continue;
            }

            $changes = [];
            if ($issue['state'] === 'closed') {
                if (! $finding->resolvable || in_array('wontfix', $issue['labels'], true)) {
                    continue;
                }
                $changes['state'] = 'open';
            }
            if ($issue['title'] !== $finding->title) {
                $changes['title'] = $finding->title;
            }
            if (self::normalize($issue['body']) !== self::normalize($body)) {
                $changes['body'] = $body;
            }

            if ($changes !== []) {
                $this->github->send('PATCH', "/repos/{$this->repository}/issues/{$issue['number']}", $changes);
                $done[] = sprintf('%s #%d: %s', isset($changes['state']) ? 'Reopened' : 'Updated', $issue['number'], $finding->title);
            }
        }

        foreach ($issues as $key => $issue) {
            if ($issue['state'] !== 'open' || ! $issue['resolvable'] || isset($reported[$key])
                || ! in_array(Str::before($key, ':'), $sources, true)) {
                continue;
            }

            $this->github->send('POST', "/repos/{$this->repository}/issues/{$issue['number']}/comments", [
                'body' => 'The watch no longer reports this, so it is resolved. Closing.',
            ]);
            $this->github->send('PATCH', "/repos/{$this->repository}/issues/{$issue['number']}", [
                'state' => 'closed',
                'state_reason' => 'completed',
            ]);
            $done[] = sprintf('Closed #%d: %s', $issue['number'], $issue['title']);
        }

        return $done;
    }

    /**
     * The watch's issues by key; of several with one key the open or newest one.
     *
     * @return array<string, array{number: int, title: string, body: string, state: string, labels: list<string>, resolvable: bool}>
     */
    private function existing(): array
    {
        $issues = [];
        foreach ($this->github->all("/repos/{$this->repository}/issues", ['labels' => 'watch', 'state' => 'all']) as $issue) {
            $body = Matrix::string($issue['body'] ?? '');
            if (isset($issue['pull_request']) || preg_match(self::MARKER, $body, $match) !== 1) {
                continue;
            }

            $labels = [];
            foreach (is_array($issue['labels'] ?? null) ? $issue['labels'] : [] as $label) {
                $labels[] = Matrix::string(is_array($label) ? ($label['name'] ?? '') : $label);
            }

            $entry = [
                'number' => (int) Matrix::string($issue['number'] ?? 0),
                'title' => Matrix::string($issue['title'] ?? ''),
                'body' => $body,
                'state' => Matrix::string($issue['state'] ?? ''),
                'labels' => $labels,
                'resolvable' => ($match[2] ?? '') !== '',
            ];

            $previous = $issues[$match[1]] ?? null;
            if ($previous === null || ($previous['state'] !== 'open' && ($entry['state'] === 'open' || $entry['number'] > $previous['number']))) {
                $issues[$match[1]] = $entry;
            }
        }

        return $issues;
    }

    private function ensureLabels(): void
    {
        $existing = array_map(
            static fn (array $label): string => Matrix::string($label['name'] ?? ''),
            $this->github->all("/repos/{$this->repository}/labels"),
        );

        foreach (self::LABELS as $name => [$color, $description]) {
            if (! in_array($name, $existing, true)) {
                $this->github->send('POST', "/repos/{$this->repository}/labels", [
                    'name' => $name,
                    'color' => $color,
                    'description' => $description,
                ]);
            }
        }
    }

    private static function normalize(string $body): string
    {
        return trim(str_replace("\r\n", "\n", $body));
    }
}
