<?php

namespace App\Parity\Watch\Sources;

use App\Parity\Matrix;
use App\Parity\Reference;
use App\Parity\Watch\Finding;
use App\Parity\Watch\GitHub;
use App\Parity\Watch\Source;
use App\Support\SemVer;
use Illuminate\Support\Str;

/**
 * Web vault builds newer than the pinned one. We install the build Vaultwarden
 * ships, so a new one reaches us when Vaultwarden takes it and the pin moves.
 */
final readonly class WebVaultReleases implements Source
{
    public const string REPOSITORY = 'dani-garcia/bw_web_builds';

    public function __construct(
        private GitHub $github,
        private Reference $reference,
    ) {}

    public function name(): string
    {
        return 'web-vault';
    }

    public function findings(): array
    {
        $pinned = SemVer::parse($this->reference->webVault);
        $newest = null;
        $newestVersion = null;

        $releases = $this->github->get('/repos/'.self::REPOSITORY.'/releases', ['per_page' => 20]);
        foreach (is_array($releases) ? $releases : [] as $release) {
            $version = is_array($release) ? SemVer::parse(ltrim(Matrix::string($release['tag_name'] ?? ''), 'v')) : null;
            if ($version === null || $pinned === null || ($release['draft'] ?? false) === true || ($release['prerelease'] ?? false) === true
                || SemVer::compare($version, $pinned) <= 0 || ($newestVersion !== null && SemVer::compare($version, $newestVersion) <= 0)) {
                continue;
            }

            $newest = $release;
            $newestVersion = $version;
        }

        if (! is_array($newest)) {
            return [];
        }

        $tag = Matrix::string($newest['tag_name'] ?? '');
        $repository = Str::after($this->reference->webUrl(), 'https://github.com/');
        $file = $this->github->get("/repos/{$repository}/contents/docker/DockerSettings.yaml");
        [$shipped] = Reference::webVaultIn((string) base64_decode(is_array($file) ? Matrix::string($file['content'] ?? '') : ''));

        return [new Finding(
            key: "web-vault:{$this->reference->webVault}",
            title: "Web vault {$tag} is out; the pin ships {$this->reference->webVault}",
            body: sprintf(
                'bw_web_builds released [%s](%s) on %s. Kennword installs the web vault Vaultwarden ships '
                ."(`web_vault` and `web_vault_digest` in `parity/reference.json`, from Vaultwarden's `docker/DockerSettings.yaml`).\n\n%s\n\n"
                .'If its notes name security fixes, check how soon Vaultwarden ships it. This issue closes itself once the pin has a web vault as new.',
                $tag, Matrix::string($newest['html_url'] ?? ''), substr(Matrix::string($newest['published_at'] ?? ''), 0, 10),
                $shipped !== null && ltrim($tag, 'v') === $shipped
                    ? 'Vaultwarden `main` ships it already, so it comes with the next move of the pin.'
                    : sprintf('Vaultwarden `main` ships %s, so it does not come with the next move of the pin yet.', $shipped ?? 'an unknown version'),
            ),
            labels: ['upstream'],
            resolvable: true,
        )];
    }
}
