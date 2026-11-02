<?php

namespace App\Parity\Watch\Sources;

use App\Parity\Matrix;
use App\Parity\Watch\Finding;
use App\Parity\Watch\Source;
use Illuminate\Support\Facades\Http;
use RuntimeException;

/**
 * Security releases of PHP: of the oldest branch composer.json allows and the
 * newest release of its major version. CI takes them by itself; servers do not.
 */
final readonly class PhpReleases implements Source
{
    public function __construct(
        private string $basePath,
    ) {}

    public function name(): string
    {
        return 'php';
    }

    public function findings(): array
    {
        $composer = json_decode((string) @file_get_contents($this->basePath.'/composer.json'), true);
        $constraint = is_array($composer) && is_array($composer['require'] ?? null) ? Matrix::string($composer['require']['php'] ?? '') : '';
        if (preg_match('/(\d+)\.(\d+)/', $constraint, $match) !== 1) {
            throw new RuntimeException('composer.json requires no PHP version.');
        }

        $findings = [];
        foreach (["{$match[1]}.{$match[2]}", $match[1]] as $branch) {
            $release = Http::timeout(30)->get('https://www.php.net/releases/index.php', ['json' => '', 'version' => $branch])->throw()->json();
            if (! is_array($release)) {
                throw new RuntimeException("php.net answered without a release for {$branch}.");
            }

            $version = Matrix::string($release['version'] ?? '');
            $tags = is_array($release['tags'] ?? null) ? $release['tags'] : [];
            if ($version === '' || ! in_array('security', $tags, true) || isset($findings[$version])) {
                continue;
            }

            $findings[$version] = new Finding(
                key: "php:{$version}",
                title: "PHP {$version} is a security release",
                body: sprintf(
                    "PHP [%s](https://www.php.net/ChangeLog-%d.php#%s) of %s fixes security issues.\n\n"
                    ."- CI takes it by itself: setup-php installs the newest PHP of the branch.\n"
                    ."- Update PHP wherever Kennword runs, for example Herd and the servers.\n"
                    .'- If a fix matters to Kennword in particular (OpenSSL, sodium, PDO, the URI extension), consider requiring it in `composer.json`.',
                    $version, (int) $version, $version, Matrix::string($release['date'] ?? ''),
                ),
                labels: ['security'],
            );
        }

        return array_values($findings);
    }
}
