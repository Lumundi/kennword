<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Archive;
use App\Models\Cipher;
use App\Models\Device;
use App\Models\Favorite;
use App\Models\Folder;
use App\Models\TwoFactor;
use App\Models\User;
use App\Support\Random;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * The personal vault of src/api/core/ciphers.rs.
 */
class CipherTest extends TestCase
{
    use UsesVaultwardenDatabase;

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

        $this->user = User::new('ciphers@example.com');
        $this->user->save();
        $device = Device::new(Random::uuid(), $this->user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->auth = ['Authorization' => 'Bearer '.LoginClaims::default($device, $this->user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];
    }

    public function test_cipher_lifecycle(): void
    {
        $folder = Folder::new($this->user->uuid, '2.folder');
        $folder->save();

        $response = $this->postJson('/api/ciphers', [
            ...$this->cipher(1, '2.login'),
            'folderId' => $folder->uuid,
            'favorite' => true,
            'fields' => [['Name' => '2.field', 'Type' => '0', 'response' => 'x']],
            'passwordHistory' => [['password' => '2.old', 'lastUsedDate' => '2026-01-02T03:04:05.123+02:00'], ['password' => null]],
            'login' => ['Username' => '2.user', 'response' => 'x', 'uris' => [['uri' => '2.uri', 'match' => '3', 'response' => 'x']]],
        ], $this->auth)->assertStatus(200)
            ->assertJsonPath('object', 'cipherDetails')
            ->assertJsonPath('name', '2.login')
            ->assertJsonPath('folderId', $folder->uuid)
            ->assertJsonPath('favorite', true)
            ->assertJsonPath('fields', [['name' => '2.field', 'type' => 0]])
            ->assertJsonPath('passwordHistory', [['lastUsedDate' => '2026-01-02T03:04:05.123000+02:00', 'password' => '2.old']])
            ->assertJsonPath('login', ['uri' => '2.uri', 'uris' => [['match' => 3, 'uri' => '2.uri']], 'username' => '2.user'])
            ->assertJsonPath('secureNote', null)
            ->assertJsonPath('permissions', ['delete' => true, 'restore' => true]);
        $id = $response->json('id');
        $this->assertIsString($id);

        $stored = Cipher::findByUuid($id);
        $this->assertNotNull($stored);
        // Stored as serde_json writes it: compact, keys sorted, original case kept.
        $this->assertSame('{"Username":"2.user","uris":[{"match":"3","uri":"2.uri"}]}', $stored->data);
        $this->assertSame('[{"Name":"2.field","Type":"0"}]', $stored->fields);

        $this->get("/api/ciphers/{$id}", $this->auth)->assertJsonPath('id', $id);
        $this->get('/api/ciphers', $this->auth)->assertJsonPath('object', 'list')->assertJsonCount(1, 'data');

        $this->putJson("/api/ciphers/{$id}", [...$this->cipher(1, '2.renamed'), 'login' => (object) [], 'archivedDate' => '2026-05-06T07:08:09Z'], $this->auth)
            ->assertJsonPath('name', '2.renamed')
            ->assertJsonPath('folderId', null)
            // Without favorite the flag stays as it is.
            ->assertJsonPath('favorite', true)
            ->assertJsonPath('archivedDate', '2026-05-06T07:08:09.000000Z');

        $this->putJson("/api/ciphers/{$id}/partial", ['folderId' => $folder->uuid, 'favorite' => false], $this->auth)
            ->assertJsonPath('folderId', $folder->uuid)
            ->assertJsonPath('favorite', false)
            ->assertJsonPath('name', '2.renamed');
        $this->assertFalse(Favorite::isFavorite($id, $this->user->uuid));

        $this->putJson("/api/ciphers/{$id}", [...$this->cipher(1, '2.again'), 'login' => (object) []], $this->auth)->assertJsonPath('archivedDate', null);
        $this->assertNull(Archive::archivedAt($id, $this->user->uuid));
    }

    public function test_invalid_ciphers(): void
    {
        $this->postJson('/api/ciphers', [...$this->cipher(1, '2.x'), 'encryptedFor' => Random::uuid(), 'login' => (object) []], $this->auth)
            ->assertStatus(422)->assertJsonPath('message', 'Invalid user cipher');
        $this->postJson('/api/ciphers', [...$this->cipher(9, '2.x'), 'login' => (object) []], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Invalid type');
        $this->postJson('/api/ciphers', $this->cipher(1, '2.x'), $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Data missing');
        $this->postJson('/api/ciphers', [...$this->cipher(1, '2.x'), 'login' => (object) [], 'notes' => str_repeat('n', 10001)], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'The field Notes exceeds the maximum encrypted value length of 10000 characters.');
        $this->postJson('/api/ciphers', [...$this->cipher(1, '2.x'), 'login' => (object) [], 'folderId' => Random::uuid()], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Invalid folder');
        $this->assertSame(0, Cipher::query()->count());
    }

    #[Parity('config:INCREASE_NOTE_SIZE_LIMIT')]
    #[Parity('config:_MAX_NOTE_SIZE')]
    public function test_the_note_size_limit_can_be_increased(): void
    {
        $long = [...$this->cipher(1, '2.x'), 'login' => (object) [], 'notes' => str_repeat('n', 10_001)];
        $this->postJson('/api/ciphers', $long, $this->auth)->assertStatus(400);
        $this->changeVaultwardenEnvironment(['INCREASE_NOTE_SIZE_LIMIT' => 'true']);
        $this->postJson('/api/ciphers', $long, $this->auth)->assertStatus(200);
        $this->postJson('/api/ciphers', [...$long, 'notes' => str_repeat('n', 100_001)], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'The field Notes exceeds the maximum encrypted value length of 100000 characters.');
    }

    public function test_stored_data_that_is_no_object_reads_as_empty(): void
    {
        // Stored as given; read back as an empty object, with the keys upstream always adds.
        $this->postJson('/api/ciphers', [...$this->cipher(1, '2.x'), 'login' => []], $this->auth)
            ->assertStatus(200)->assertJsonPath('login', ['uri' => null, 'uris' => null]);
        $this->assertSame('[]', Cipher::query()->value('data'));

        $cipher = Cipher::query()->firstOrFail();
        $cipher->fields = '[{"Name":"2.a"},{}]';
        $cipher->password_history = '[{"password":"2.p"},[]]';
        $cipher->save();
        $this->get("/api/ciphers/{$cipher->uuid}", $this->auth)
            ->assertJsonPath('fields', [['name' => '2.a', 'type' => 1], ['type' => 1]])
            ->assertJsonPath('passwordHistory', []);
    }

    public function test_stale_client_copies_are_rejected(): void
    {
        $id = $this->postJson('/api/ciphers', [...$this->cipher(1, '2.x'), 'login' => (object) []], $this->auth)->json('id');
        $this->assertIsString($id);

        $this->putJson("/api/ciphers/{$id}", [...$this->cipher(1, '2.y'), 'login' => (object) [], 'lastKnownRevisionDate' => '2020-01-01T00:00:00Z'], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'The client copy of this cipher is out of date. Resync the client and try again.');
        // Unparsable dates are only logged.
        $this->putJson("/api/ciphers/{$id}", [...$this->cipher(1, '2.y'), 'login' => (object) [], 'lastKnownRevisionDate' => 'yesterday'], $this->auth)
            ->assertStatus(200);
    }

    public function test_ciphers_of_other_users_are_hidden(): void
    {
        $other = User::new('other@example.com');
        $other->save();
        $cipher = Cipher::new(2, '2.theirs');
        $cipher->user_uuid = $other->uuid;
        $cipher->data = '{"type":0}';
        $cipher->save();

        $this->get("/api/ciphers/{$cipher->uuid}", $this->auth)->assertStatus(400)->assertJsonPath('message', 'Cipher is not owned by user');
        $this->putJson("/api/ciphers/{$cipher->uuid}", [...$this->cipher(2, '2.mine'), 'secureNote' => []], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Cipher is not write accessible');
        $this->putJson("/api/ciphers/{$cipher->uuid}/partial", ['favorite' => true], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Cipher does not exist');
        $this->get('/api/ciphers', $this->auth)->assertJsonCount(0, 'data');
    }

    public function test_trash_and_deletion(): void
    {
        $first = $this->create('2.first');
        $second = $this->create('2.second');
        $third = $this->create('2.third');

        $this->put("/api/ciphers/{$first}/delete", [], $this->auth)->assertStatus(200)->assertContent('');
        $this->get("/api/ciphers/{$first}", $this->auth)->assertJsonPath('deletedDate', fn (mixed $date): bool => is_string($date));

        $this->putJson('/api/ciphers/restore', ['ids' => [$first, $first]], $this->auth)
            ->assertJsonPath('object', 'list')->assertJsonCount(1, 'data')->assertJsonPath('data.0.deletedDate', null);
        $this->put("/api/ciphers/{$first}/restore", [], $this->auth)->assertJsonPath('id', $first);

        $this->putJson('/api/ciphers/delete', ['ids' => [$first, $second]], $this->auth)->assertStatus(200);
        $this->assertNotNull(Cipher::findByUuid($second)?->deleted_at);

        $this->delete("/api/ciphers/{$first}", [], $this->auth)->assertStatus(200);
        $this->assertNull(Cipher::findByUuid($first));
        $this->post("/api/ciphers/{$second}/delete", [], $this->auth)->assertStatus(200);
        $this->deleteJson('/api/ciphers', ['ids' => [$third, $first]], $this->auth)->assertStatus(400)->assertJsonPath('message', "Cipher doesn't exist");
        // The ones before the error are gone.
        $this->assertSame(0, Cipher::query()->count());

        $this->deleteJson('/api/ciphers', ['id' => [$first]], $this->auth)->assertStatus(422);
        $this->put('/api/ciphers/not-a-uuid/delete', [], $this->auth)->assertStatus(422);
    }

    public function test_moving_ciphers(): void
    {
        $folder = Folder::new($this->user->uuid, '2.folder');
        $folder->save();
        $first = $this->create('2.first');
        $second = $this->create('2.second');

        $this->postJson('/api/ciphers/move', ['folderId' => $folder->uuid, 'ids' => [$first]], $this->auth)->assertStatus(200)->assertContent('');
        $this->assertSame($folder->uuid, $this->folderOf($first));
        $this->assertNull($this->folderOf($second));

        $this->putJson('/api/ciphers/move', ['folderId' => Random::uuid(), 'ids' => [$first]], $this->auth)->assertStatus(400)->assertJsonPath('message', 'Invalid folder');
        $this->putJson('/api/ciphers/move', ['folderId' => '', 'ids' => [$first, Random::uuid()]], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Not all ciphers are moved! 1 of the selected 2 were moved.');
        $this->assertNull($this->folderOf($first));

        // No ids means no filter upstream: every cipher moves.
        $this->postJson('/api/ciphers/move', ['folderId' => $folder->uuid, 'ids' => []], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Not all ciphers are moved! 2 of the selected 0 were moved.');
        $this->assertSame($folder->uuid, $this->folderOf($second));
        // Vaultwarden f1c7eccd: the revision of the user moves once for the whole batch.
        $revisions = 0;
        DB::connection('vaultwarden')->listen(static function (QueryExecuted $query) use (&$revisions): void {
            $revisions += preg_match('/^update "users" set "updated_at"/i', $query->sql);
        });
        $this->postJson('/api/ciphers/move', ['folderId' => null, 'ids' => [$first, $second]], $this->auth)->assertStatus(200);
        $this->assertSame(1, $revisions);
        $this->assertNull($this->folderOf($second));
    }

    public function test_archiving_ciphers(): void
    {
        $first = $this->create('2.first');
        $second = $this->create('2.second');

        $archived = $this->put("/api/ciphers/{$first}/archive", [], $this->auth)->assertStatus(200)->json('archivedDate');
        $this->assertIsString($archived);
        $this->putJson('/api/ciphers/archive', ['ids' => [$first, $second]], $this->auth)->assertJsonCount(2, 'data');
        $this->assertNotNull(Archive::archivedAt($second, $this->user->uuid));

        $this->put("/api/ciphers/{$first}/unarchive", [], $this->auth)->assertJsonPath('archivedDate', null);
        $this->putJson('/api/ciphers/unarchive', ['ids' => [$second]], $this->auth)->assertJsonPath('data.0.archivedDate', null);
        $this->put('/api/ciphers/'.Random::uuid().'/archive', [], $this->auth)->assertStatus(400)->assertJsonPath('message', "Cipher doesn't exist");
    }

    public function test_purging_the_personal_vault(): void
    {
        $this->user->setPassword('hash', null, false, null);
        $this->user->save();
        Folder::new($this->user->uuid, '2.folder')->save();
        $this->create('2.first');

        $this->postJson('/api/ciphers/purge', ['masterPasswordHash' => 'wrong'], $this->auth)->assertStatus(400)->assertJsonPath('message', 'Invalid password');
        $this->call('POST', '/api/ciphers/purge', [], [], [], $this->transformHeadersToServerVars($this->auth), '{}')->assertStatus(400)->assertJsonPath('message', 'No validation provided');
        $this->postJson('/api/ciphers/purge', ['masterPasswordHash' => 'hash', 'otp' => '123'], $this->auth)->assertStatus(400)->assertJsonPath('message', 'No validation provided');
        $this->postJson('/api/ciphers/purge', ['otp' => '123'], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Protected action token not found, try sending the code again or restart the process');
        $this->assertSame(1, Cipher::query()->count());

        $this->postJson('/api/ciphers/purge', ['MasterPasswordHash' => 'hash'], $this->auth)->assertStatus(200)->assertContent('');
        $this->assertSame(0, Cipher::query()->count());
        $this->assertSame(0, Folder::query()->count());

        $this->postJson('/api/ciphers/purge?organizationId='.Random::uuid(), ['masterPasswordHash' => 'hash'], $this->auth)->assertStatus(401);
    }

    public function test_purging_with_a_mailed_code(): void
    {
        $action = new TwoFactor;
        $action->uuid = Random::uuid();
        $action->user_uuid = $this->user->uuid;
        $action->atype = TwoFactor::TYPE_PROTECTED_ACTIONS;
        $action->enabled = true;
        $action->data = json_encode(['token' => '123456', 'token_sent' => time(), 'attempts' => 0], JSON_THROW_ON_ERROR);
        $action->last_used = 0;
        $action->save();

        $this->postJson('/api/ciphers/purge', ['otp' => '000000'], $this->auth)->assertStatus(400)->assertJsonPath('message', 'Token is invalid');
        $this->assertStringContainsString('"attempts":1', (string) TwoFactor::findByUserAndType($this->user->uuid, TwoFactor::TYPE_PROTECTED_ACTIONS)?->data);

        $this->postJson('/api/ciphers/purge', ['otp' => '123456'], $this->auth)->assertStatus(200);
        $this->assertNull(TwoFactor::findByUserAndType($this->user->uuid, TwoFactor::TYPE_PROTECTED_ACTIONS));
    }

    public function test_creating_through_the_share_route(): void
    {
        $this->postJson('/api/ciphers/create', ['cipher' => [...$this->cipher(2, '2.created'), 'secureNote' => ['type' => 0]], 'collectionIds' => []], $this->auth)
            ->assertStatus(200)->assertJsonPath('name', '2.created')->assertJsonPath('object', 'cipherDetails');
        $this->postJson('/api/ciphers/admin', ['Cipher' => [...$this->cipher(2, '2.admin'), 'secureNote' => ['type' => 0]], 'CollectionIds' => []], $this->auth)
            ->assertStatus(200)->assertJsonPath('name', '2.admin');
        $this->assertSame(2, Cipher::query()->count());

        // A failure removes the cipher that was saved first.
        $this->postJson('/api/ciphers/create', ['cipher' => $this->cipher(2, '2.broken'), 'collectionIds' => []], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Data missing');
        $this->postJson('/api/ciphers/create', ['cipher' => [...$this->cipher(2, '2.org'), 'secureNote' => [], 'organizationId' => Random::uuid()],
            'collectionIds' => [Random::uuid()]], $this->auth)->assertStatus(400)->assertJsonPath('message', 'Invalid collection ID provided');
        $this->assertCount(2, Cipher::all());

        $this->postJson('/api/ciphers/create', ['cipher' => [...$this->cipher(2, '2.x'), 'encryptedFor' => Random::uuid()], 'collectionIds' => []], $this->auth)
            ->assertStatus(422)->assertJsonPath('message', 'Invalid user cipher');
        $this->postJson('/api/ciphers/create', ['cipher' => $this->cipher(2, '2.x')], $this->auth)->assertStatus(422);
    }

    public function test_the_organization_of_a_cipher_does_not_change_through_an_update(): void
    {
        // Vaultwarden 64ae55ce: moving into an organization only through the share routes.
        $id = $this->create('2.personal');
        $update = [...$this->cipher(2, '2.moved'), 'secureNote' => ['type' => 0], 'organizationId' => Random::uuid()];
        foreach (['put', 'post'] as $method) {
            $this->json($method, "/api/ciphers/{$id}", $update, $this->auth)
                ->assertStatus(400)->assertJsonPath('message', 'Organization mismatch. Please resync the client before updating the cipher');
            $this->json($method, "/api/ciphers/{$id}/admin", $update, $this->auth)
                ->assertStatus(400)->assertJsonPath('message', 'Organization mismatch. Please resync the client before updating the cipher');
        }
        $this->assertSame('2.personal', Cipher::findByUuid($id)?->name);

        $this->putJson("/api/ciphers/{$id}", [...$this->cipher(2, '2.renamed'), 'secureNote' => ['type' => 0]], $this->auth)
            ->assertStatus(200)->assertJsonPath('name', '2.renamed');
    }

    public function test_the_admin_routes_only_take_organization_ciphers(): void
    {
        $id = $this->create('2.personal');
        foreach (['put', 'post'] as $method) {
            $this->json($method, "/api/ciphers/{$id}/admin", [...$this->cipher(2, '2.x'), 'secureNote' => ['type' => 0]], $this->auth)
                ->assertStatus(404)->assertJsonPath('message', 'Resource not found.');
        }
        $this->assertSame('2.personal', Cipher::findByUuid($id)?->name);
    }

    public function test_sharing_needs_an_organization_and_collections(): void
    {
        $id = $this->create('2.personal');
        $cipher = [...$this->cipher(2, '2.x'), 'secureNote' => ['type' => 0]];
        foreach (['put', 'post'] as $method) {
            $this->json($method, "/api/ciphers/{$id}/share", ['cipher' => $cipher, 'collectionIds' => [Random::uuid()]], $this->auth)
                ->assertStatus(400)->assertJsonPath('message', 'Cipher OrganizationId is required.');
            $this->json($method, "/api/ciphers/{$id}/share", ['cipher' => [...$cipher, 'organizationId' => Random::uuid()], 'collectionIds' => []], $this->auth)
                ->assertStatus(400)->assertJsonPath('message', 'You must select at least one collection.');
        }
        $this->putJson('/api/ciphers/share', ['ciphers' => [[...$cipher, 'id' => $id]], 'collectionIds' => [Random::uuid()]], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Cipher OrganizationId is required.');
        $this->assertSame('2.personal', Cipher::findByUuid($id)?->name);
    }

    public function test_import_ignores_the_organization(): void
    {
        $this->postJson('/api/ciphers/import', ['folders' => [], 'folderRelationships' => [], 'ciphers' => [
            [...$this->cipher(2, '2.a'), 'secureNote' => ['type' => 0], 'organizationId' => Random::uuid()],
        ]], $this->auth)->assertStatus(200);
        $cipher = Cipher::query()->where('name', '2.a')->first();
        $this->assertNull($cipher?->organization_uuid);
        $this->assertSame($this->user->uuid, $cipher?->user_uuid);
    }

    public function test_import(): void
    {
        $existing = Folder::new($this->user->uuid, '2.existing');
        $existing->save();

        $this->postJson('/api/ciphers/import', [
            'folders' => [['name' => '2.new', 'id' => Random::uuid()], ['name' => '2.ignored', 'id' => $existing->uuid], ['name' => '2.second']],
            'folderRelationships' => [['key' => 0, 'value' => 0], ['key' => 1, 'value' => 2], ['key' => 1, 'value' => 1], ['key' => 2, 'value' => 9]],
            'ciphers' => [
                [...$this->cipher(2, '2.a'), 'secureNote' => ['type' => 0], 'folderId' => Random::uuid()],
                [...$this->cipher(2, '2.b'), 'secureNote' => ['type' => 0]],
                [...$this->cipher(1, '2.c'), 'login' => [], 'lastKnownRevisionDate' => '2000-01-01T00:00:00Z'],
            ],
        ], $this->auth)->assertStatus(200)->assertContent('');

        $this->assertSame(['2.existing', '2.new', '2.second'], Folder::query()->orderBy('name')->pluck('name')->all());
        $new = Folder::query()->where('name', '2.new')->value('uuid');
        $this->assertIsString($new);
        $this->assertSame($new, $this->folderOfNamed('2.a'));
        $this->assertSame($existing->uuid, $this->folderOfNamed('2.b'));
        $this->assertNull($this->folderOfNamed('2.c'));
    }

    public function test_import_validation(): void
    {
        $response = $this->postJson('/api/ciphers/import', ['folders' => [['name' => '2.f']], 'folderRelationships' => [], 'ciphers' => [
            [...$this->cipher(2, '2.a'), 'secureNote' => [], 'notes' => str_repeat('n', 10001)],
            [...$this->cipher(2, '2.b'), 'secureNote' => [], 'passwordHistory' => [['password' => '2.ok'], ['password' => null]]],
        ]], $this->auth)->assertStatus(400);
        $this->assertSame([
            'message' => 'The model state is invalid.',
            'object' => 'error',
            'validationErrors' => [
                'Ciphers[0].Notes' => ['The field Notes exceeds the maximum encrypted value length of 10000 characters.'],
                'Ciphers[1].Notes' => ['The password history contains a `null` value. Only strings are allowed.'],
            ],
        ], $response->json());
        $this->assertSame(0, Folder::query()->count());

        // Items are saved one by one; an invalid one stops the rest.
        $this->postJson('/api/ciphers/import', ['folders' => [], 'folderRelationships' => [], 'ciphers' => [
            [...$this->cipher(2, '2.a'), 'secureNote' => []],
            [...$this->cipher(9, '2.b'), 'secureNote' => []],
            [...$this->cipher(2, '2.c'), 'secureNote' => []],
        ]], $this->auth)->assertStatus(400)->assertJsonPath('message', 'Invalid type');
        $this->assertSame(['2.a'], Cipher::query()->pluck('name')->all());

        $this->postJson('/api/ciphers/import', ['folders' => [], 'ciphers' => []], $this->auth)->assertStatus(422);
        $this->postJson('/api/ciphers/import', ['folders' => [], 'folderRelationships' => [['key' => -1, 'value' => 0]], 'ciphers' => []], $this->auth)->assertStatus(422);
    }

    private function folderOfNamed(string $name): ?string
    {
        return Cipher::query()->where('name', $name)->first()?->folderUuid($this->user->uuid);
    }

    private function folderOf(string $cipherId): ?string
    {
        return Cipher::findByUuid($cipherId)?->folderUuid($this->user->uuid);
    }

    private function create(string $name): string
    {
        $id = $this->postJson('/api/ciphers', [...$this->cipher(2, $name), 'secureNote' => ['type' => 0]], $this->auth)->assertStatus(200)->json('id');
        $this->assertIsString($id);

        return $id;
    }

    /**
     * @return array<string, mixed>
     */
    private function cipher(int $type, string $name): array
    {
        return ['type' => $type, 'name' => $name, 'encryptedFor' => $this->user->uuid];
    }
}
