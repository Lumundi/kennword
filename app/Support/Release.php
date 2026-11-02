<?php

namespace App\Support;

use Composer\InstalledVersions;

/**
 * The version of Kennword, which Vaultwarden takes from git when it is
 * built (VW_VERSION). Here Composer records the checkout it installed.
 */
final class Release
{
    public const string NAME = 'Kennword';

    /**
     * The GitHub repository whose releases and commits are the newer versions.
     */
    public const string REPOSITORY = 'Lumundi/kennword';

    /**
     * The tag of a release without its "v", otherwise the first 8 characters
     * of the commit; "-" when neither is known.
     */
    public static function installed(): string
    {
        $root = InstalledVersions::getRootPackage();
        if (self::isTagged()) {
            return ltrim($root['pretty_version'], 'v');
        }

        return $root['reference'] === null ? '-' : substr($root['reference'], 0, 8);
    }

    /**
     * Whether the installed version is a release rather than a commit.
     */
    public static function isTagged(): bool
    {
        $version = InstalledVersions::getRootPackage()['pretty_version'];

        return ! str_starts_with($version, 'dev-') && ! str_ends_with($version, '-dev');
    }

    /**
     * The Vaultwarden release this implementation mirrors (parity/reference.json).
     */
    public static function vaultwarden(): string
    {
        return config()->string('vaultwarden.version');
    }
}
