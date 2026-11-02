<?php

namespace App\Parity;

use JsonException;
use RuntimeException;

/**
 * The pinned Vaultwarden commit this implementation is compared against
 * (parity/reference.json) and its local checkout (reference/vaultwarden).
 */
final readonly class Reference
{
    /**
     * @param  array<string, string>  $webVaultSource  The source of the web vault build: the tag of each
     *                                                 GitHub repository ("owner/name") it is built from,
     *                                                 which the release archives carry along (GPL-3.0)
     */
    public function __construct(
        public string $repository,
        public string $commit,
        public string $release,
        public string $webVault,
        public string $webVaultDigest,
        public string $checkout,
        public array $webVaultSource = [],
    ) {}

    /**
     * @throws JsonException
     */
    public static function load(string $basePath): self
    {
        $pin = json_decode((string) file_get_contents($basePath.'/parity/reference.json'), true, flags: JSON_THROW_ON_ERROR);

        if (! is_array($pin)) {
            throw new RuntimeException('parity/reference.json must contain an object.');
        }

        return new self(
            repository: self::string($pin, 'repository'),
            commit: self::string($pin, 'commit'),
            release: self::string($pin, 'release'),
            webVault: self::string($pin, 'web_vault'),
            webVaultDigest: self::string($pin, 'web_vault_digest'),
            checkout: $basePath.'/reference/vaultwarden',
            webVaultSource: self::webVaultSource($pin),
        );
    }

    /**
     * The checked out commit, or null when there is no checkout.
     */
    public function checkedOutCommit(): ?string
    {
        $head = $this->checkout.'/.git/HEAD';

        return is_file($head) ? trim((string) file_get_contents($head)) : null;
    }

    public function assertCheckedOut(): void
    {
        if ($this->checkedOutCommit() !== $this->commit) {
            throw new RuntimeException("The reference checkout is not at {$this->commit}. Run `php artisan parity:fetch` first.");
        }
    }

    /**
     * The web vault must be the one Vaultwarden's Docker images ship at the
     * pinned commit (docker/DockerSettings.yaml), which kennword:web-vault installs.
     */
    public function assertWebVaultMatches(): void
    {
        [$version, $digest] = self::webVaultIn((string) @file_get_contents($this->checkout.'/docker/DockerSettings.yaml'));

        if ($version !== $this->webVault || $digest !== $this->webVaultDigest) {
            throw new RuntimeException(sprintf(
                'Vaultwarden ships web vault %s (%s); set "web_vault" and "web_vault_digest" in parity/reference.json to match.',
                $version ?? 'unknown', $digest ?? 'no digest',
            ));
        }
    }

    /**
     * @param  array<mixed>  $pin
     * @return array<string, string>
     */
    private static function webVaultSource(array $pin): array
    {
        $source = [];
        foreach (is_array($pin['web_vault_source'] ?? null) ? $pin['web_vault_source'] : [] as $repository => $tag) {
            if (! is_string($repository) || preg_match('#^[\w.-]+/[\w.-]+$#', $repository) !== 1 || ! is_string($tag) || $tag === '') {
                throw new RuntimeException('"web_vault_source" in parity/reference.json must map GitHub repositories ("owner/name") to tags.');
            }
            $source[$repository] = $tag;
        }
        if ($source === []) {
            throw new RuntimeException('parity/reference.json is missing "web_vault_source".');
        }

        return $source;
    }

    /**
     * The web vault version and image digest of a docker/DockerSettings.yaml.
     *
     * @return array{?string, ?string}
     */
    public static function webVaultIn(string $settings): array
    {
        return [
            preg_match('/^vault_version:\s*"v?([^"]+)"/m', $settings, $match) === 1 ? $match[1] : null,
            preg_match('/^vault_image_digest:\s*"([^"]+)"/m', $settings, $match) === 1 ? $match[1] : null,
        ];
    }

    /**
     * The repository's web address, e.g. https://github.com/dani-garcia/vaultwarden.
     */
    public function webUrl(): string
    {
        return preg_replace('/\.git$/', '', $this->repository) ?? $this->repository;
    }

    /**
     * @param  array<mixed>  $pin
     */
    private static function string(array $pin, string $key): string
    {
        $value = $pin[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw new RuntimeException("parity/reference.json is missing \"{$key}\".");
        }

        return $value;
    }
}
