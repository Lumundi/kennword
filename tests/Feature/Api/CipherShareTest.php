<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Cipher;
use App\Models\Device;
use App\Models\Membership;
use App\Models\User;
use App\Support\Random;
use Illuminate\Support\Facades\DB;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * The share routes only take the user's own ciphers (Vaultwarden 5ad0c6d4, after the pin; Bitwarden's PutShare and
 * PutShareMany). Before, write access was enough, so a member could link an organization's cipher to any other
 * collection they may write to.
 */
class CipherShareTest extends TestCase
{
    use UsesVaultwardenDatabase;

    /**
     * @var array<string, string>
     */
    private array $owner;

    /**
     * @var array<string, string>
     */
    private array $member;

    private User $ownerUser;

    private User $memberUser;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');

        [$this->ownerUser, $this->owner] = $this->login('owner@example.com');
        [$this->memberUser, $this->member] = $this->login('member@example.com');
    }

    public function test_an_organization_cipher_cannot_be_shared_into_other_collections(): void
    {
        $org = $this->string($this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $this->owner)->assertStatus(200)->json('id'));
        $memberId = $this->addMember($org);
        // The member may write to both collections, but only sees the passwords of the second one.
        $hidden = $this->collection($org, '2.hidden', $memberId, hidePasswords: true);
        $open = $this->collection($org, '2.open', $memberId, hidePasswords: false);

        $cipher = $this->string($this->postJson('/api/ciphers/create', ['cipher' => $this->note($this->ownerUser, '2.secret', ['organizationId' => $org]),
            'collectionIds' => [$hidden]], $this->owner)->assertStatus(200)->json('id'));
        $update = $this->note($this->memberUser, '2.secret', ['organizationId' => $org]);

        foreach (['put', 'post'] as $method) {
            $this->json($method, "/api/ciphers/{$cipher}/share", ['cipher' => $update, 'collectionIds' => [$open]], $this->member)
                ->assertStatus(404)->assertJsonPath('message', "Cipher doesn't exist");
        }
        $this->putJson('/api/ciphers/share', ['ciphers' => [[...$update, 'id' => $cipher]], 'collectionIds' => [$open]], $this->member)
            ->assertStatus(400)->assertJsonPath('message', 'Trying to share ciphers that you do not own.');
        // Unknown ciphers are not anyone's either.
        $this->putJson('/api/ciphers/'.Random::uuid().'/share', ['cipher' => $update, 'collectionIds' => [$open]], $this->member)
            ->assertStatus(404)->assertJsonPath('message', "Cipher doesn't exist");

        $this->assertSame([$hidden], DB::table('ciphers_collections')->where('cipher_uuid', $cipher)->pluck('collection_uuid')->all());
        $this->assertSame('2.secret', Cipher::findByUuid($cipher)?->name);
    }

    public function test_bulk_sharing_writes_nothing_when_one_cipher_is_not_owned(): void
    {
        $org = $this->string($this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $this->owner)->assertStatus(200)->json('id'));
        $memberId = $this->addMember($org);
        $collection = $this->collection($org, '2.shared', $memberId, hidePasswords: false);
        $foreign = $this->string($this->postJson('/api/ciphers/create', ['cipher' => $this->note($this->ownerUser, '2.foreign', ['organizationId' => $org]),
            'collectionIds' => [$collection]], $this->owner)->assertStatus(200)->json('id'));
        $mine = $this->string($this->postJson('/api/ciphers', $this->note($this->memberUser, '2.mine'), $this->member)->assertStatus(200)->json('id'));

        $this->putJson('/api/ciphers/share', ['ciphers' => [
            $this->note($this->memberUser, '2.mine', ['organizationId' => $org, 'id' => $mine]),
            $this->note($this->memberUser, '2.foreign', ['organizationId' => $org, 'id' => $foreign]),
        ], 'collectionIds' => [$collection]], $this->member)->assertStatus(400)->assertJsonPath('message', 'Trying to share ciphers that you do not own.');
        $this->assertNull(Cipher::findByUuid($mine)?->organization_uuid);

        // The member's own cipher is shared as before.
        $this->putJson("/api/ciphers/{$mine}/share", ['cipher' => $this->note($this->memberUser, '2.mine', ['organizationId' => $org]),
            'collectionIds' => [$collection]], $this->member)->assertStatus(200)->assertJsonPath('organizationId', $org);
    }

    public function test_bulk_collections_do_not_reveal_hidden_passwords(): void
    {
        // Unlike Vaultwarden, which only asks for write access: like PUT /ciphers/{id}/collections, a member whose
        // passwords are hidden cannot link the cipher to a collection where they are not.
        $org = $this->string($this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $this->owner)->assertStatus(200)->json('id'));
        $memberId = $this->addMember($org);
        $hidden = $this->collection($org, '2.hidden', $memberId, hidePasswords: true);
        $open = $this->collection($org, '2.open', $memberId, hidePasswords: false);
        $cipher = $this->string($this->postJson('/api/ciphers/create', ['cipher' => $this->note($this->ownerUser, '2.secret', ['organizationId' => $org]),
            'collectionIds' => [$hidden]], $this->owner)->assertStatus(200)->json('id'));

        $this->postJson('/api/ciphers/bulk-collections', ['organizationId' => $org, 'cipherIds' => [$cipher], 'collectionIds' => [$open],
            'removeCollections' => false], $this->member)->assertStatus(200);
        $this->postJson("/api/ciphers/{$cipher}/collections", ['collectionIds' => [$hidden, $open]], $this->member)
            ->assertStatus(400)->assertJsonPath('message', 'Collection cannot be changed');
        $this->assertSame([$hidden], DB::table('ciphers_collections')->where('cipher_uuid', $cipher)->pluck('collection_uuid')->all());

        // With visible passwords it works as before.
        $other = $this->string($this->postJson('/api/ciphers/create', ['cipher' => $this->note($this->ownerUser, '2.visible', ['organizationId' => $org]),
            'collectionIds' => [$open]], $this->owner)->assertStatus(200)->json('id'));
        $this->postJson('/api/ciphers/bulk-collections', ['organizationId' => $org, 'cipherIds' => [$other], 'collectionIds' => [$hidden],
            'removeCollections' => false], $this->member)->assertStatus(200);
        $this->assertCount(2, DB::table('ciphers_collections')->where('cipher_uuid', $other)->get());
    }

    private function collection(string $org, string $name, string $memberId, bool $hidePasswords): string
    {
        return $this->string($this->postJson("/api/organizations/{$org}/collections", ['name' => $name, 'groups' => [],
            'users' => [['id' => $memberId, 'readOnly' => false, 'hidePasswords' => $hidePasswords, 'manage' => false]]], $this->owner)
            ->assertStatus(200)->json('id'));
    }

    private function addMember(string $orgId): string
    {
        $this->postJson("/api/organizations/{$orgId}/users/invite", ['emails' => ['member@example.com'], 'groups' => [], 'type' => 2], $this->owner)->assertStatus(200);
        $memberId = $this->string(Membership::query()->where('user_uuid', $this->memberUser->uuid)->value('uuid'));
        $this->postJson("/api/organizations/{$orgId}/users/{$memberId}/confirm", ['key' => '4.member-key'], $this->owner)->assertStatus(200);

        return $memberId;
    }

    /**
     * @param  array<string, mixed>  $more
     * @return array<string, mixed>
     */
    private function note(User $user, string $name, array $more = []): array
    {
        return ['type' => 2, 'name' => $name, 'encryptedFor' => $user->uuid, 'secureNote' => ['type' => 0], ...$more];
    }

    /**
     * @return array{User, array<string, string>}
     */
    private function login(string $email): array
    {
        $user = User::new($email);
        $user->setPassword('hash', 'user-key', false, null);
        $user->save();
        $device = Device::new(Random::uuid(), $user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);

        return [$user, ['Authorization' => 'Bearer '.LoginClaims::default($device, $user, AuthMethod::Password, 'cli', $jwt)->token($jwt)]];
    }

    private function string(mixed $value): string
    {
        $this->assertIsString($value);

        return $value;
    }
}
