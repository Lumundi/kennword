<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Cipher;
use App\Models\Device;
use App\Models\Invitation;
use App\Models\Membership;
use App\Models\Organization;
use App\Models\OrgCollection;
use App\Models\User;
use App\Support\Random;
use Illuminate\Support\Facades\Log;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * Organizations, members, collections and organization ciphers
 * (src/api/core/organizations.rs and ciphers.rs).
 */
class OrganizationTest extends TestCase
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

    private User $memberUser;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');

        [, $this->owner] = $this->login('owner@example.com');
        [$this->memberUser, $this->member] = $this->login('member@example.com');
    }

    public function test_organization_lifecycle(): void
    {
        $org = $this->createOrganization();
        $this->get("/api/organizations/{$org}", $this->owner)->assertStatus(200)
            ->assertJsonPath('name', '2.org')->assertJsonPath('billingEmail', 'billing@example.com')->assertJsonPath('hasPublicAndPrivateKeys', false);
        $this->get('/api/accounts/profile', $this->owner)->assertJsonPath('organizations.0.id', $org)->assertJsonPath('organizations.0.type', 0);

        $this->putJson("/api/organizations/{$org}", ['billingEmail' => 'NEW@example.com', 'name' => '2.renamed'], $this->owner)
            ->assertJsonPath('name', '2.renamed')->assertJsonPath('billingEmail', 'new@example.com');
        $this->putJson("/api/organizations/{$org}", ['billingEmail' => 'nope', 'name' => '2.x'], $this->owner)
            ->assertStatus(400)->assertJsonPath('message', 'BillingEmail nope is not a valid email address');
        $this->putJson("/api/organizations/{$org}", ['billingEmail' => "o'neil", 'name' => '2.x'], $this->owner)
            ->assertStatus(400)->assertJsonPath('message', "BillingEmail o\\'neil is not a valid email address");

        $this->postJson("/api/organizations/{$org}/keys", ['encryptedPrivateKey' => '2.private', 'publicKey' => 'public'], $this->owner)
            ->assertJsonPath('publicKey', 'public')->assertJsonPath('privateKey', '2.private');
        $this->postJson("/api/organizations/{$org}/keys", ['encryptedPrivateKey' => '2.x', 'publicKey' => 'x'], $this->owner)
            ->assertStatus(400)->assertJsonPath('message', 'Organization Keys already exist');
        $this->get("/api/organizations/{$org}/public-key", $this->owner)->assertJsonPath('publicKey', 'public');

        // Others are no members.
        $this->get("/api/organizations/{$org}", $this->member)->assertStatus(401);
        $this->get('/api/organizations/'.Random::uuid(), $this->owner)->assertStatus(401);

        $this->json('DELETE', "/api/organizations/{$org}", ['masterPasswordHash' => 'wrong'], $this->owner)->assertStatus(400)->assertJsonPath('message', 'Invalid password');
        $this->json('DELETE', "/api/organizations/{$org}", ['masterPasswordHash' => 'hash'], $this->owner)->assertStatus(200);
        $this->assertSame(0, Organization::query()->count());
        $this->assertSame(0, OrgCollection::query()->count());
        $this->assertSame(0, Membership::query()->count());
    }

    public function test_members(): void
    {
        $org = $this->createOrganization();
        $collection = $this->string($this->get("/api/organizations/{$org}/collections", $this->owner)->json('data.0.id'));

        // Without mail, users with a password join as accepted; new ones get an invitation.
        $this->postJson("/api/organizations/{$org}/users/invite", ['emails' => ['member@example.com', 'NEW@example.com'], 'groups' => [], 'type' => 2,
            'collections' => [['id' => $collection, 'readOnly' => true, 'hidePasswords' => false, 'manage' => false]]], $this->owner)->assertStatus(200);
        $this->assertNotNull(Invitation::findByMail('new@example.com'));
        $this->postJson("/api/organizations/{$org}/users/invite", ['emails' => ['member@example.com'], 'groups' => [], 'type' => 2], $this->owner)
            ->assertStatus(400)->assertJsonPath('message', 'User already in organization: member@example.com');
        $this->postJson("/api/organizations/{$org}/users/invite", ['emails' => ['x@example.com'], 'groups' => [], 'type' => 7], $this->owner)
            ->assertStatus(400)->assertJsonPath('message', 'Invalid type');

        $members = $this->get("/api/organizations/{$org}/users?includeCollections=true", $this->owner)->assertJsonCount(3, 'data');
        $byEmail = [];
        foreach ((array) $members->json('data') as $member) {
            $this->assertIsArray($member);
            $byEmail[$this->string($member['email'])] = $member;
        }
        $memberId = $this->string($byEmail['member@example.com']['id']);
        $newId = $this->string($byEmail['new@example.com']['id']);
        $this->assertSame(1, $byEmail['member@example.com']['status']);
        $this->assertSame(0, $byEmail['new@example.com']['status']);
        $this->assertSame([['hidePasswords' => false, 'id' => $collection, 'manage' => false, 'readOnly' => true]], $byEmail['member@example.com']['collections']);

        $this->get("/api/organizations/{$org}/users/mini-details", $this->owner)->assertJsonCount(3, 'data');
        $this->get("/api/organizations/{$org}/users/{$memberId}", $this->owner)->assertJsonPath('email', 'member@example.com')->assertJsonPath('collections', []);

        // Accepted members see the organization in the newer list, without key.
        $this->get('/api/accounts/profile', $this->member)->assertJsonPath('organizations', [])->assertJsonPath('organizationsNew.0.key', null);
        $this->get("/api/organizations/{$org}/users", $this->member)->assertStatus(401);

        $this->postJson("/api/organizations/{$org}/users/{$newId}/confirm", ['key' => '4.k'], $this->owner)->assertStatus(400)->assertJsonPath('message', 'User in invalid state');
        $this->call('POST', "/api/organizations/{$org}/users/{$memberId}/confirm", [], [], [], $this->transformHeadersToServerVars($this->owner), '{}')
            ->assertStatus(400)->assertJsonPath('message', 'Key or UserId is not set, unable to process request');
        $this->postJson("/api/organizations/{$org}/users/confirm", ['keys' => [['id' => $memberId, 'key' => '4.k'], ['id' => $newId, 'key' => '4.k']]], $this->owner)
            ->assertJsonPath('data.0.error', '')->assertJsonPath('data.1.error', 'User in invalid state');
        $this->get('/api/accounts/profile', $this->member)->assertJsonPath('organizations.0.key', '4.k');

        $this->putJson("/api/organizations/{$org}/users/{$memberId}", ['type' => 4, 'permissions' => ['editAnyCollection' => true, 'deleteAnyCollection' => true, 'createNewCollections' => true]], $this->owner)
            ->assertStatus(200);
        $this->get("/api/organizations/{$org}/users/{$memberId}", $this->owner)->assertJsonPath('type', 4)->assertJsonPath('permissions.editAnyCollection', true);

        $this->put("/api/organizations/{$org}/users/{$memberId}/revoke", [], $this->owner)->assertStatus(200);
        $this->get("/api/organizations/{$org}/users/{$memberId}", $this->owner)->assertJsonPath('status', -1);
        $this->get("/api/organizations/{$org}", $this->member)->assertStatus(401);
        $this->put("/api/organizations/{$org}/users/{$memberId}/revoke", [], $this->owner)->assertStatus(400)->assertJsonPath('message', 'User is already revoked');
        $this->putJson("/api/organizations/{$org}/users/restore", ['ids' => [$memberId, $newId]], $this->owner)
            ->assertJsonPath('data.0.error', '')->assertJsonPath('data.1.error', '');
        $this->get("/api/organizations/{$org}/users/{$memberId}", $this->owner)->assertJsonPath('status', 2);

        $ownerId = $this->string($byEmail['owner@example.com']['id']);
        $this->put("/api/organizations/{$org}/users/{$ownerId}/revoke", [], $this->owner)->assertStatus(400)->assertJsonPath('message', 'You cannot revoke yourself');
        $this->delete("/api/organizations/{$org}/users/{$ownerId}", [], $this->owner)->assertStatus(400)->assertJsonPath('message', "Can't delete the last owner");

        // Vaultwarden be5d3ad9 and 6ed6921c: the error's message per member, the details and the escaped id in the log.
        $log = Log::spy();
        $this->deleteJson("/api/organizations/{$org}/users", ['ids' => [$newId, "o'x"]], $this->owner)
            ->assertJsonPath('data.0.error', '')->assertJsonPath('data.1.error', "User to delete isn't member of the organization");
        $log->shouldHaveReceived('warning')->with("Unable to delete member o\\'x: User to delete isn't member of the organization");
        $this->assertNull(Invitation::findByMail('new@example.com'));
        $this->post("/api/organizations/{$org}/leave", [], $this->member)->assertStatus(200);
        $this->post("/api/organizations/{$org}/leave", [], $this->owner)->assertStatus(400)->assertJsonPath('message', "The last owner can't leave");
        $this->assertSame(1, Membership::query()->count());
    }

    /**
     * Error messages print emails with Rust's escape_debug.
     */
    public function test_invitations_of_unusual_emails(): void
    {
        $org = $this->createOrganization();
        $invite = fn (string $email) => $this->postJson("/api/organizations/{$org}/users/invite", ['emails' => [$email], 'groups' => [], 'type' => 2], $this->owner);

        $invite("o'neil@example.com")->assertStatus(200);
        $invite("o'neil@example.com")->assertStatus(400)->assertJsonPath('message', "User already in organization: o\\'neil@example.com");
        $invite("o'neil\x01@example.com")->assertStatus(400)
            ->assertJsonPath('message', "Invitation email o\\'neil\\u{1}@example.com is not a valid email address");
    }

    /**
     * Settings change before the first request, which resolves the controller.
     */
    #[Parity('config:INVITATIONS_ALLOWED')]
    public function test_invitations_without_invitations_allowed(): void
    {
        $this->changeVaultwardenEnvironment(['INVITATIONS_ALLOWED' => 'false']);
        $org = $this->createOrganization();

        $this->postJson("/api/organizations/{$org}/users/invite", ['emails' => ["o'neil@example.com"], 'groups' => [], 'type' => 2], $this->owner)
            ->assertStatus(400)->assertJsonPath('message', "User does not exist: o\\'neil@example.com");
        $this->assertNull(User::findByMail("o'neil@example.com"));
    }

    #[Parity('config:ORG_CREATION_USERS')]
    public function test_organization_creation_can_be_limited_to_some_users(): void
    {
        $this->changeVaultwardenEnvironment(['ORG_CREATION_USERS' => 'someone@example.com']);
        $this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first', 'key' => '4.owner-key',
            'name' => '2.org', 'planType' => 0], $this->owner)->assertStatus(400)->assertJsonPath('message', 'User not allowed to create organizations');
        $this->changeVaultwardenEnvironment(['ORG_CREATION_USERS' => 'someone@example.com,owner@example.com']);
        $this->createOrganization();
    }

    public function test_collections_and_organization_ciphers(): void
    {
        $org = $this->createOrganization();
        $memberId = $this->addMember($org);
        $first = $this->string($this->get("/api/organizations/{$org}/collections", $this->owner)->json('data.0.id'));

        $second = $this->string($this->postJson("/api/organizations/{$org}/collections", ['name' => '2.second', 'groups' => [], 'externalId' => '',
            'users' => [['id' => $memberId, 'readOnly' => true, 'hidePasswords' => true, 'manage' => false]]], $this->owner)
            ->assertJsonPath('object', 'collectionDetails')->assertJsonPath('manage', true)->assertJsonPath('externalId', null)->json('id'));
        $this->get("/api/organizations/{$org}/collections/{$second}/users", $this->owner)
            ->assertExactJson([['hidePasswords' => true, 'id' => $memberId, 'manage' => false, 'readOnly' => true]]);
        $this->get("/api/organizations/{$org}/collections/details", $this->owner)->assertJsonCount(2, 'data');
        $this->get("/api/organizations/{$org}/collections/{$second}/details", $this->owner)->assertJsonPath('assigned', true);
        $this->get('/api/collections', $this->member)->assertJsonCount(1, 'data')->assertJsonPath('data.0.id', $second);

        // An organization cipher in the second collection: the member may read it, without passwords.
        $cipher = $this->string($this->postJson('/api/ciphers/create', ['cipher' => ['type' => 2, 'name' => '2.shared', 'encryptedFor' => $this->ownerId(),
            'secureNote' => ['type' => 0], 'organizationId' => $org], 'collectionIds' => [$second]], $this->owner)
            ->assertStatus(200)->assertJsonPath('organizationId', $org)->assertJsonPath('collectionIds', [$second])->json('id'));
        $this->assertNull(Cipher::findByUuid($cipher)?->user_uuid);

        $this->get("/api/ciphers/{$cipher}", $this->member)->assertJsonPath('edit', false)->assertJsonPath('viewPassword', false)->assertJsonPath('collectionIds', []);
        $this->get('/api/sync', $this->member)->assertJsonCount(1, 'ciphers')->assertJsonPath('ciphers.0.collectionIds', [$second])
            ->assertJsonPath('collections.0.readOnly', true)->assertJsonPath('collections.0.hidePasswords', true)
            ->assertJsonPath('profile.organizations.0.id', $org);
        $this->putJson("/api/ciphers/{$cipher}", ['type' => 2, 'name' => '2.edit', 'encryptedFor' => $this->memberUser->uuid, 'secureNote' => [], 'organizationId' => $org], $this->member)
            ->assertStatus(400)->assertJsonPath('message', 'Cipher is not write accessible');

        // The owner moves it into the first collection too.
        $moved = $this->putJson("/api/ciphers/{$cipher}/collections_v2", ['collectionIds' => [$first, $second]], $this->owner)
            ->assertJsonPath('object', 'optionalCipherDetails');
        $this->assertEqualsCanonicalizing([$first, $second], $moved->json('cipher.collectionIds'));
        $details = $this->get("/api/ciphers/organization-details?organizationId={$org}", $this->owner)->assertJsonCount(1, 'data')->assertJsonMissingPath('data.0.edit');
        $this->assertEqualsCanonicalizing([$first, $second], $details->json('data.0.collectionIds'));
        $this->get("/api/ciphers/organization-details?organizationId={$org}", $this->member)->assertStatus(401);

        $this->putJson("/api/organizations/{$org}/collections/{$second}", ['name' => '2.renamed', 'groups' => [],
            'users' => [['id' => $memberId, 'readOnly' => false, 'hidePasswords' => false, 'manage' => false]]], $this->owner)->assertJsonPath('name', '2.renamed');
        $this->get("/api/ciphers/{$cipher}", $this->member)->assertJsonPath('edit', true)->assertJsonPath('viewPassword', true);

        // A personal cipher shared into the organization.
        $personal = $this->string($this->postJson('/api/ciphers', ['type' => 2, 'name' => '2.mine', 'encryptedFor' => $this->memberUser->uuid, 'secureNote' => []], $this->member)->json('id'));
        $this->putJson("/api/ciphers/{$personal}/share", ['cipher' => ['type' => 2, 'name' => '2.mine', 'encryptedFor' => $this->memberUser->uuid, 'secureNote' => [],
            'organizationId' => $org], 'collectionIds' => [$first]], $this->member)->assertStatus(400)->assertJsonPath('message', 'No rights to modify the collection');
        $this->putJson("/api/ciphers/{$personal}/share", ['cipher' => ['type' => 2, 'name' => '2.mine', 'encryptedFor' => $this->memberUser->uuid, 'secureNote' => [],
            'organizationId' => $org], 'collectionIds' => [$second]], $this->member)->assertStatus(200)->assertJsonPath('organizationId', $org);

        $this->postJson('/api/ciphers/bulk-collections', ['organizationId' => $org, 'cipherIds' => [$personal], 'collectionIds' => [$first], 'removeCollections' => false], $this->owner)
            ->assertStatus(200);
        $this->assertEqualsCanonicalizing([$first, $second], $this->get("/api/ciphers/{$personal}", $this->owner)->json('collectionIds'));

        $this->deleteJson("/api/organizations/{$org}/collections", ['ids' => [$second]], $this->owner)->assertStatus(200);
        $this->get('/api/sync', $this->member)->assertJsonCount(0, 'ciphers');

        $this->json('POST', "/api/ciphers/purge?organizationId={$org}", ['masterPasswordHash' => 'hash'], $this->owner)->assertStatus(200);
        $this->assertSame(0, Cipher::query()->count());
    }

    /**
     * The manager guard checks the collection the route works on: an encoded
     * slash, which Laravel's router splits on, must not move the collection id
     * out of the path, so that the guard checks the collectionId query field.
     */
    public function test_a_manager_only_reaches_collections_they_manage(): void
    {
        $org = $this->createOrganization();
        $victim = $this->string($this->get("/api/organizations/{$org}/collections", $this->owner)->json('data.0.id'));
        $this->postJson("/api/organizations/{$org}/users/invite", ['emails' => ['member@example.com'], 'groups' => [], 'type' => 3], $this->owner)->assertStatus(200);
        $memberId = $this->string(Membership::query()->where('user_uuid', $this->memberUser->uuid)->value('uuid'));
        $this->postJson("/api/organizations/{$org}/users/{$memberId}/confirm", ['key' => '4.member-key'], $this->owner)->assertStatus(200);
        $managed = $this->string($this->postJson("/api/organizations/{$org}/collections", ['name' => '2.managed', 'groups' => [], 'externalId' => '',
            'users' => [['id' => $memberId, 'readOnly' => false, 'hidePasswords' => false, 'manage' => true]]], $this->owner)->json('id'));

        $takeOver = ['name' => '2.taken', 'groups' => [], 'users' => [['id' => $memberId, 'readOnly' => false, 'hidePasswords' => false, 'manage' => true]]];
        $this->putJson("/api/organizations/{$org}/collections/{$managed}", $takeOver, $this->member)->assertStatus(200);
        $this->putJson("/api/organizations/{$org}/collections/{$victim}", $takeOver, $this->member)->assertStatus(401);
        $this->putJson("/api/organizations/{$org}/collections%2F{$victim}?collectionId={$managed}", $takeOver, $this->member)->assertStatus(401);
        $this->get("/api/organizations/{$org}/collections/{$victim}%2Fusers?collectionId={$managed}", $this->member)->assertStatus(401);
        $this->deleteJson("/api/organizations/{$org}/collections%2F{$victim}?collectionId={$managed}", [], $this->member)->assertStatus(401);

        $this->assertSame('2.first', OrgCollection::query()->where('uuid', $victim)->value('name'));
        $this->assertFalse(OrgCollection::isCollManageableByUser($victim, $this->memberUser->uuid));
    }

    private function createOrganization(): string
    {
        return $this->string($this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $this->owner)->assertStatus(200)->assertJsonPath('object', 'organization')->json('id'));
    }

    /**
     * Invites and confirms the member; returns the membership id.
     */
    private function addMember(string $orgId): string
    {
        $this->postJson("/api/organizations/{$orgId}/users/invite", ['emails' => ['member@example.com'], 'groups' => [], 'type' => 2], $this->owner)->assertStatus(200);
        $memberId = Membership::query()->where('user_uuid', $this->memberUser->uuid)->value('uuid');
        $this->assertIsString($memberId);
        $this->postJson("/api/organizations/{$orgId}/users/{$memberId}/confirm", ['key' => '4.member-key'], $this->owner)->assertStatus(200);

        return $memberId;
    }

    private function ownerId(): string
    {
        return (string) User::findByMail('owner@example.com')?->uuid;
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
