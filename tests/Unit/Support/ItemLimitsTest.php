<?php

namespace Tests\Unit\Support;

use App\Http\ApiError;
use App\Support\ItemLimits;
use Closure;
use Tests\TestCase;

/**
 * The limits of Bitwarden's ImportCiphersController and CiphersController,
 * and the settings of Kennword's that change them.
 */
class ItemLimitsTest extends TestCase
{
    public function test_bitwardens_numbers_by_default(): void
    {
        $this->assertPasses(static fn () => ItemLimits::checkImport(7000, 2000, 7000));
        $this->assertRefused('You cannot import this much data at once.', static fn () => ItemLimits::checkImport(7001, 0, 0));
        $this->assertRefused('You cannot import this much data at once.', static fn () => ItemLimits::checkImport(0, 2001, 0));
        $this->assertRefused('You cannot import this much data at once.', static fn () => ItemLimits::checkImport(0, 0, 7001));

        $this->assertPasses(static fn () => ItemLimits::checkOrganizationImport(40_000, 2000, 80_000, 2000, 80_000));
        foreach ([[40_001, 0, 0, 0, 0], [0, 2001, 0, 0, 0], [0, 0, 80_001, 0, 0], [0, 0, 0, 2001, 0], [0, 0, 0, 0, 80_001]] as $counts) {
            $this->assertRefused('You cannot import this much data at once.', static fn () => ItemLimits::checkOrganizationImport(...$counts));
        }

        $this->assertPasses(static fn () => ItemLimits::checkBulk(500, 'move'));
        $this->assertRefused('You can only move up to 500 items at a time.', static fn () => ItemLimits::checkBulk(501, 'move'));
    }

    public function test_the_numbers_of_items_are_settings(): void
    {
        config(['vaultwarden.item_limits' => ['import' => '10', 'org_import' => '10', 'bulk' => '+10']]);
        $this->assertRefused('You cannot import this much data at once.', static fn () => ItemLimits::checkImport(11, 0, 0));
        // The assignments follow the items, folders and collections do not.
        $this->assertPasses(static fn () => ItemLimits::checkImport(10, 2000, 10));
        $this->assertRefused('You cannot import this much data at once.', static fn () => ItemLimits::checkImport(0, 0, 11));
        $this->assertPasses(static fn () => ItemLimits::checkOrganizationImport(10, 2000, 20, 2000, 20));
        $this->assertRefused('You cannot import this much data at once.', static fn () => ItemLimits::checkOrganizationImport(0, 0, 21, 0, 0));
        $this->assertRefused('You can only restore up to 10 items at a time.', static fn () => ItemLimits::checkBulk(11, 'restore'));

        // 0 lifts every limit of its kind.
        config(['vaultwarden.item_limits' => ['import' => '0', 'org_import' => 0, 'bulk' => '0']]);
        $this->assertPasses(static fn () => ItemLimits::checkImport(PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX));
        $this->assertPasses(static fn () => ItemLimits::checkOrganizationImport(PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX));
        $this->assertPasses(static fn () => ItemLimits::checkBulk(PHP_INT_MAX, 'delete'));

        // Like Vaultwarden's settings, a value that is no unsigned 32-bit number counts as unset.
        foreach (['many', '-1', ' 10', '4294967296', '', true, -1] as $value) {
            config(['vaultwarden.item_limits.bulk' => $value]);
            $this->assertRefused('You can only delete up to 500 items at a time.', static fn () => ItemLimits::checkBulk(501, 'delete'));
        }
    }

    public function test_deleting_for_good_advises_the_purge(): void
    {
        $this->assertRefused('You can only delete up to 500 items at a time. Consider using the "Purge Vault" option instead.',
            static fn () => ItemLimits::checkBulk(501, 'delete', ' Consider using the "Purge Vault" option instead.'));
    }

    private function assertPasses(Closure $check): void
    {
        $check();
        $this->addToAssertionCount(1);
    }

    private function assertRefused(string $message, Closure $check): void
    {
        try {
            $check();
            $this->fail("Not refused: {$message}");
        } catch (ApiError $error) {
            $this->assertSame($message, $error->getMessage());
        }
    }
}
