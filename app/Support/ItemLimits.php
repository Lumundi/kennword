<?php

namespace App\Support;

use App\Config\SettingType;
use App\Http\ApiError;

/**
 * How many items one import or bulk request may carry: as many as Bitwarden's
 * servers take (ImportCiphersController, CiphersController), with their
 * messages. Bitwarden's self-hosted server and Vaultwarden have no such limits.
 * The numbers of items are settings of Kennword's (config/vaultwarden.php),
 * the other limits follow them; 0 lifts them. Like Vaultwarden's settings,
 * a value that is no unsigned 32-bit number counts as unset.
 */
final class ItemLimits
{
    /**
     * Items of a personal import, of an organization import and of a bulk action.
     */
    public const array DEFAULTS = ['import' => 7000, 'org_import' => 40000, 'bulk' => 500];

    /**
     * Folders of an import and collections of an organization import.
     */
    public const int FOLDERS = 2000;

    private const string TOO_MUCH = 'You cannot import this much data at once.';

    /**
     * POST /api/ciphers/import: the items and as many folder assignments, 2000 folders.
     *
     * @throws ApiError
     */
    public static function checkImport(int $ciphers, int $folders, int $folderRelationships): void
    {
        $limit = self::limit('import');
        if ($limit > 0 && ($ciphers > $limit || $folderRelationships > $limit || $folders > self::FOLDERS)) {
            throw ApiError::message(self::TOO_MUCH);
        }
    }

    /**
     * POST /api/ciphers/import-organization: the items, twice as many collection
     * and folder assignments, 2000 collections and folders.
     *
     * @throws ApiError
     */
    public static function checkOrganizationImport(int $ciphers, int $collections, int $collectionRelationships, int $folders, int $folderRelationships): void
    {
        $limit = self::limit('org_import');
        if ($limit > 0 && ($ciphers > $limit || $collectionRelationships > 2 * $limit || $folderRelationships > 2 * $limit
            || $collections > self::FOLDERS || $folders > self::FOLDERS)) {
            throw ApiError::message(self::TOO_MUCH);
        }
    }

    /**
     * A bulk action on items, named as in the message: "delete", "restore", ...
     *
     * @param  string  $advice  Added to the message, as Bitwarden does for deleting for good
     *
     * @throws ApiError
     */
    public static function checkBulk(int $items, string $action, string $advice = ''): void
    {
        $limit = self::limit('bulk');
        if ($limit > 0 && $items > $limit) {
            throw ApiError::message("You can only {$action} up to {$limit} items at a time.{$advice}");
        }
    }

    /**
     * @param  key-of<self::DEFAULTS>  $key
     */
    private static function limit(string $key): int
    {
        $value = config("vaultwarden.item_limits.{$key}");
        $limit = is_string($value) ? SettingType::U32->parse($value) : $value;

        return is_int($limit) && $limit >= 0 ? $limit : self::DEFAULTS[$key];
    }
}
