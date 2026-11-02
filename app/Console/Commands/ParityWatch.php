<?php

namespace App\Console\Commands;

use App\Parity\Matrix;
use App\Parity\Reference;
use App\Parity\Upstream\Counterparts;
use App\Parity\Upstream\Report;
use App\Parity\Watch\GitHub;
use App\Parity\Watch\Issues;
use App\Parity\Watch\Source;
use App\Parity\Watch\Sources\ComposerAudit;
use App\Parity\Watch\Sources\ComposerUpdates;
use App\Parity\Watch\Sources\PhpReleases;
use App\Parity\Watch\Sources\RustCrates;
use App\Parity\Watch\Sources\VaultwardenAdvisories;
use App\Parity\Watch\Sources\VaultwardenMain;
use App\Parity\Watch\Sources\VaultwardenReleases;
use App\Parity\Watch\Sources\WebVaultReleases;
use App\Support\Release;
use Illuminate\Console\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

class ParityWatch extends Command
{
    /**
     * @var string
     */
    protected $signature = 'parity:watch
        {--issues : Open, update and close the GitHub issues of the findings}
        {--source=* : Only these sources}
        {--repository= : The repository of the issues, by default $GITHUB_REPOSITORY or Kennword\'s}';

    /**
     * @var string
     */
    protected $description = 'Look for advisories and upstream changes (docs/maintenance.md); -v shows the issue texts';

    public function handle(): int
    {
        $only = array_filter((array) $this->option('source'), is_string(...));
        $failed = false;
        $ran = [];
        $findings = [];

        foreach ($this->sources() as $source) {
            if ($only !== [] && ! in_array($source->name(), $only, true)) {
                continue;
            }

            try {
                $found = $source->findings();
            } catch (Throwable $exception) {
                $this->components->error("{$source->name()}: {$exception->getMessage()}");
                $failed = true;

                continue;
            }

            $ran[] = $source->name();
            $findings = [...$findings, ...$found];
            $this->components->twoColumnDetail($source->name(), match (count($found)) {
                0 => 'nothing',
                1 => '1 finding',
                default => count($found).' findings',
            });

            foreach ($found as $finding) {
                $this->line('  › '.OutputFormatter::escape($finding->title));
                if ($this->output->isVerbose()) {
                    $this->output->writeln("\n{$finding->body}\n", OutputInterface::OUTPUT_RAW);
                }
            }
        }

        if ($this->option('issues')) {
            $repository = $this->option('repository');
            $repository = is_string($repository) && $repository !== '' ? $repository : (getenv('GITHUB_REPOSITORY') ?: Release::REPOSITORY);

            foreach (new Issues(GitHub::fromEnvironment(), $repository)->sync($findings, $ran) as $done) {
                $this->components->info($done);
            }
        }

        return $failed ? self::FAILURE : self::SUCCESS;
    }

    /**
     * @return list<Source>
     */
    private function sources(): array
    {
        $reference = Reference::load(base_path());
        $github = GitHub::fromEnvironment();
        $counterparts = new Counterparts(Matrix::load(base_path('parity/matrix.json'))->items, base_path());

        return [
            new ComposerAudit(base_path()),
            new ComposerUpdates(base_path()),
            new VaultwardenReleases($github, $reference),
            new VaultwardenAdvisories($github, $reference, $counterparts),
            new VaultwardenMain($reference, new Report($reference, $counterparts)),
            new WebVaultReleases($github, $reference),
            new PhpReleases(base_path()),
            new RustCrates($reference),
        ];
    }
}
