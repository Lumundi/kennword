<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Cipher;
use App\Models\Device;
use App\Models\Folder;
use App\Models\OrgCollection;
use App\Models\User;
use App\Support\Random;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * Imports and bulk actions carry at most as many items as Bitwarden's servers
 * take (ImportCiphersController, CiphersController), unless the settings of
 * Kennword's (IMPORT_ITEM_LIMIT, ORG_IMPORT_ITEM_LIMIT, BULK_ITEM_LIMIT) say otherwise.
 */
class ItemLimitTest extends TestCase
{
    use UsesVaultwardenDatabase;

    private const string TOO_MUCH = 'You cannot import this much data at once.';

    /**
     * @var array<string, string>
     */
    private array $auth;

    private User $user;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');

        $this->user = User::new('limits@example.com');
        $this->user->save();
        $device = Device::new(Random::uuid(), $this->user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->auth = ['Authorization' => 'Bearer '.LoginClaims::default($device, $this->user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];
    }

    public function test_a_personal_import_is_limited(): void
    {
        // tests/Unit/Support/ItemLimitsTest checks Bitwarden's numbers; these requests stay small.
        $this->import(folders: 2001)->assertStatus(400)->assertJsonPath('message', self::TOO_MUCH);
        $this->assertSame(0, Folder::query()->count());

        config(['vaultwarden.item_limits.import' => '3']);
        $this->import(ciphers: 4)->assertStatus(400)->assertJsonPath('message', self::TOO_MUCH);
        $this->import(relationships: 4)->assertStatus(400)->assertJsonPath('message', self::TOO_MUCH);
        $this->assertSame(0, Cipher::query()->count());
        // Folder assignments of ciphers that are not there are ignored.
        $this->import(ciphers: 3, folders: 2, relationships: 3)->assertStatus(200);
        $this->assertSame(3, Cipher::query()->count());

        config(['vaultwarden.item_limits.import' => '0']);
        $this->import(ciphers: 4, relationships: 4)->assertStatus(200);
        $this->assertSame(7, Cipher::query()->count());
    }

    public function test_bulk_actions_take_as_many_items_as_bitwardens_by_default(): void
    {
        $ids = array_map(static fn (): string => Random::uuid(), range(1, 501));
        $hardDelete = 'You can only delete up to 500 items at a time. Consider using the "Purge Vault" option instead.';

        foreach ([
            ['DELETE', '/api/ciphers', $hardDelete],
            ['POST', '/api/ciphers/delete', $hardDelete],
            ['DELETE', '/api/ciphers/admin', $hardDelete],
            ['POST', '/api/ciphers/delete-admin', $hardDelete],
            ['PUT', '/api/ciphers/delete', 'You can only delete up to 500 items at a time.'],
            ['PUT', '/api/ciphers/delete-admin', 'You can only delete up to 500 items at a time.'],
            ['PUT', '/api/ciphers/restore', 'You can only restore up to 500 items at a time.'],
            ['PUT', '/api/ciphers/restore-admin', 'You can only restore up to 500 items at a time.'],
            ['POST', '/api/ciphers/move', 'You can only move up to 500 items at a time.'],
            ['PUT', '/api/ciphers/move', 'You can only move up to 500 items at a time.'],
            ['PUT', '/api/ciphers/archive', 'You can only archive up to 500 items at a time.'],
            ['PUT', '/api/ciphers/unarchive', 'You can only unarchive up to 500 items at a time.'],
        ] as [$method, $path, $message]) {
            $this->json($method, $path, ['ids' => $ids], $this->auth)->assertStatus(400)->assertJsonPath('message', $message);
            // One fewer passes the limit and fails at the first unknown cipher.
            $this->assertNotSame($message, $this->json($method, $path, ['ids' => array_slice($ids, 1)], $this->auth)->json('message'), "{$method} {$path}");
        }

        $this->putJson('/api/ciphers/share', $this->share($ids), $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'You can only share up to 500 items at a time.');
        $this->putJson('/api/ciphers/share', $this->share(array_slice($ids, 1)), $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Trying to share ciphers that you do not own.');
    }

    public function test_the_bulk_limit_can_be_set(): void
    {
        $first = $this->create('2.first');
        $second = $this->create('2.second');
        $third = $this->create('2.third');

        config(['vaultwarden.item_limits.bulk' => '2']);
        $this->putJson('/api/ciphers/delete', ['ids' => [$first, $second, $third]], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'You can only delete up to 2 items at a time.');
        $this->assertSame(0, Cipher::query()->whereNotNull('deleted_at')->count());
        // Bitwarden counts the ids as sent.
        $this->putJson('/api/ciphers/delete', ['ids' => [$first, $second, $second]], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'You can only delete up to 2 items at a time.');
        $this->putJson('/api/ciphers/delete', ['ids' => [$first, $second]], $this->auth)->assertStatus(200);
        $this->assertSame(2, Cipher::query()->whereNotNull('deleted_at')->count());

        config(['vaultwarden.item_limits.bulk' => '0']);
        $this->putJson('/api/ciphers/restore', ['ids' => [$first, $second, $third]], $this->auth)->assertStatus(200)->assertJsonCount(3, 'data');

        // Like Vaultwarden's settings, a value that is no number counts as unset.
        config(['vaultwarden.item_limits.bulk' => 'many']);
        $ids = array_map(static fn (): string => Random::uuid(), range(1, 501));
        $this->putJson('/api/ciphers/restore', ['ids' => $ids], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'You can only restore up to 500 items at a time.');
    }

    public function test_an_organization_import_is_limited(): void
    {
        $org = $this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $this->auth)->assertStatus(200)->json('id');
        $this->assertIsString($org);
        $import = fn (int $ciphers = 0, int $collections = 0, int $relationships = 0, int $folders = 0, int $folderRelationships = 0): TestResponse => $this->postJson(
            "/api/ciphers/import-organization?organizationId={$org}", [
                'ciphers' => array_map(fn (int $i): array => [...$this->cipher("2.item{$i}"), 'organizationId' => $org], $ciphers > 0 ? range(1, $ciphers) : []),
                'collections' => array_map(static fn (int $i): array => ['name' => "2.collection{$i}"], $collections > 0 ? range(1, $collections) : []),
                'collectionRelationships' => self::relations($relationships),
                // Upstream reads no folders here.
                'folders' => array_map(static fn (int $i): array => ['name' => "2.folder{$i}"], $folders > 0 ? range(1, $folders) : []),
                'folderRelationships' => self::relations($folderRelationships),
            ], $this->auth);

        $import(collections: 2001)->assertStatus(400)->assertJsonPath('message', self::TOO_MUCH);
        $import(folders: 2001)->assertStatus(400)->assertJsonPath('message', self::TOO_MUCH);
        $this->assertSame(1, OrgCollection::findByOrganization($org)->count());

        config(['vaultwarden.item_limits.org_import' => '2']);
        $import(ciphers: 3)->assertStatus(400)->assertJsonPath('message', self::TOO_MUCH);
        // Twice as many assignments as items.
        $import(ciphers: 2, collections: 2, relationships: 5)->assertStatus(400)->assertJsonPath('message', self::TOO_MUCH);
        $import(ciphers: 2, collections: 2, folderRelationships: 5)->assertStatus(400)->assertJsonPath('message', self::TOO_MUCH);
        $this->assertSame(0, Cipher::findByOrg($org)->count());
        $import(ciphers: 2, collections: 2, relationships: 4, folderRelationships: 4)->assertStatus(200);
        $this->assertSame(2, Cipher::findByOrg($org)->count());
    }

    /**
     * @return TestResponse<Response>
     */
    private function import(int $ciphers = 0, int $folders = 0, int $relationships = 0): TestResponse
    {
        return $this->postJson('/api/ciphers/import', [
            'ciphers' => array_map(fn (int $i): array => $this->cipher("2.item{$i}"), $ciphers > 0 ? range(1, $ciphers) : []),
            'folders' => array_map(static fn (int $i): array => ['name' => "2.folder{$i}"], $folders > 0 ? range(1, $folders) : []),
            'folderRelationships' => self::relations($relationships),
        ], $this->auth);
    }

    /**
     * The given ids into a collection of another organization.
     *
     * @param  list<string>  $ids
     * @return array<string, mixed>
     */
    private function share(array $ids): array
    {
        return ['collectionIds' => [Random::uuid()], 'ciphers' => array_map(
            fn (string $id): array => [...$this->cipher('2.shared'), 'id' => $id, 'organizationId' => Random::uuid()], $ids)];
    }

    /**
     * Item i to collection or folder i modulo 2, which is there in the tests that pass.
     *
     * @return list<array{key: int, value: int}>
     */
    private static function relations(int $count): array
    {
        return array_map(static fn (int $i): array => ['key' => intdiv($i, 2), 'value' => $i % 2], $count > 0 ? range(0, $count - 1) : []);
    }

    private function create(string $name): string
    {
        $id = $this->postJson('/api/ciphers', $this->cipher($name), $this->auth)->assertStatus(200)->json('id');
        $this->assertIsString($id);

        return $id;
    }

    /**
     * @return array<string, mixed>
     */
    private function cipher(string $name): array
    {
        return ['type' => 2, 'name' => $name, 'secureNote' => ['type' => 0], 'encryptedFor' => $this->user->uuid];
    }
}
