<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\LoginClaims;
use App\Models\Device;
use App\Models\Membership;
use App\Models\OrgPolicy;
use App\Models\User;
use App\Support\Random;
use Illuminate\Testing\TestResponse;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * Organization policies (src/api/core/organizations.rs, src/db/models/org_policy.rs).
 */
class PolicyTest extends TestCase
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

    public function test_reading_and_setting_policies(): void
    {
        $org = $this->createOrganization();
        $policies = "/api/organizations/{$org}/policies";

        $this->get($policies, $this->owner)->assertExactJson(['continuationToken' => null, 'data' => [], 'object' => 'list']);
        $this->get("{$policies}/8", $this->owner)->assertJsonPath('enabled', false)->assertJsonPath('data', null)->assertJsonPath('canToggleState', true);
        $this->get("{$policies}/4", $this->owner)->assertStatus(400)->assertJsonPath('message', 'Invalid or unsupported policy type');
        $this->get("{$policies}/+02", $this->owner)->assertStatus(200)->assertJsonPath('type', 2);
        $this->get("{$policies}/2147483648", $this->owner)->assertStatus(404);
        $this->putJson("{$policies}/nope", ['policy' => ['enabled' => true]], $this->owner)->assertStatus(422);
        $this->putJson("{$policies}/2", ['policy' => []], $this->owner)->assertStatus(422);

        // The data is stored as serde writes it: keys sorted, none as null.
        $this->putJson("{$policies}/2", ['policy' => ['enabled' => true, 'data' => ['useUpper' => true, 'minLength' => 12]]], $this->owner)
            ->assertStatus(200)->assertJsonPath('data', ['minLength' => 12, 'useUpper' => true])->assertJsonPath('enabled', true);
        $policy = OrgPolicy::findByOrgAndType($org, 2);
        $this->assertSame('{"minLength":12,"useUpper":true}', $policy?->data);
        $this->putJson("{$policies}/2", ['policy' => ['enabled' => false]], $this->owner)->assertJsonPath('id', $policy->uuid);
        $this->assertSame('null', OrgPolicy::findByOrgAndType($org, 2)?->data);
        $this->assertSame(1, OrgPolicy::query()->count());

        $this->get($policies, $this->owner)->assertJsonCount(1, 'data');
        $this->get("{$policies}/master-password", $this->owner)->assertJsonPath('type', 1)->assertJsonPath('enabled', false);
        $this->get('/api/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password')
            ->assertJsonPath('organizationId', '00000000-01DC-01DC-01DC-000000000000');
    }

    public function test_enabling_policies_revokes_excluded_members(): void
    {
        $org = $this->createOrganization();
        $memberId = $this->addMember($org);
        // The member owns another organization.
        $this->postJson('/api/organizations', ['billingEmail' => 'b@example.com', 'collectionName' => '2.c', 'key' => '4.k', 'name' => '2.own', 'planType' => 0], $this->member)
            ->assertStatus(200);

        $this->putJson("/api/organizations/{$org}/policies/3", ['policy' => ['enabled' => true, 'data' => null]], $this->owner)->assertStatus(200);
        $this->assertSame(Membership::STATUS_CONFIRMED - 128, Membership::findByUuid($memberId)?->status);
        $this->put("/api/organizations/{$org}/users/{$memberId}/restore", [], $this->owner)
            ->assertStatus(400)->assertJsonPath('message', "Cannot restore because the organization policy forbids being part of other organization (membership {$memberId})");

        // Owners are exempt from the 2FA policy.
        $this->putJson("/api/organizations/{$org}/policies/0", ['policy' => ['enabled' => true, 'data' => null]], $this->owner)->assertStatus(200);
        $this->get("/api/organizations/{$org}/users", $this->owner)->assertJsonPath('data.0.status', Membership::STATUS_CONFIRMED);
    }

    public function test_the_fill_assist_policy(): void
    {
        $org = $this->createOrganization();
        $put = fn (int $type, bool $enabled, mixed $data): TestResponse => $this->putJson("/api/organizations/{$org}/policies/{$type}",
            ['policy' => ['enabled' => $enabled, 'data' => $data]], $this->owner);

        $put(22, true, ['rulesUrl' => 'https://rules.example'])->assertStatus(400)
            ->assertJsonPath('message', 'Turn on the Single organization policy because it is required for the Activate fill assist policy.');
        $put(22, false, ['rulesUrl' => 5])->assertStatus(400)->assertJsonPath('message', 'Invalid data for FillAssist policy: rulesUrl has an invalid value.');
        $put(3, true, null)->assertStatus(200);

        $put(22, true, null)->assertStatus(400)->assertJsonPath('message', 'The RulesUrl field is required.');
        $put(22, true, ['rulesUrl' => " \u{3000}"])->assertStatus(400)->assertJsonPath('message', 'The RulesUrl field is required.');
        $put(22, true, ['rulesUrl' => 'https://a.example', 'RulesUrl' => 'https://b.example'])->assertStatus(400)
            ->assertJsonPath('message', 'Invalid data for FillAssist policy: rulesUrl has an invalid value.');
        $put(22, true, 'https://rules.example')->assertStatus(400)->assertJsonPath('message', 'Invalid data for FillAssist policy: rulesUrl has an invalid value.');
        $put(22, true, [])->assertStatus(400)->assertJsonPath('message', 'Invalid data for FillAssist policy: rulesUrl has an invalid value.');
        $put(22, true, ['rulesUrl' => 'mailto:rules@example.com'])->assertStatus(400)
            ->assertJsonPath('message', 'The RulesUrl field is not a valid fully-qualified http, https, or ftp URL.');
        $put(22, true, ['RulesUrl' => 'ftp://rules.example'])->assertStatus(400)->assertJsonPath('message', 'RulesUrl must use HTTPS.');
        // Like any derived struct, the data may be a sequence of its fields.
        $put(22, true, ['https://rules.example'])->assertStatus(200)->assertJsonPath('data', ['https://rules.example']);
        $put(22, true, ['RulesUrl' => 'https://rules.example/feed'])->assertStatus(200)->assertJsonPath('enabled', true);

        $put(3, false, null)->assertStatus(400)->assertJsonPath('message', 'Turn off the Activate fill assist policy because it requires the Single organization policy.');
        $put(22, false, null)->assertStatus(200);
        $put(3, false, null)->assertStatus(200);
        $this->assertSame([false, false], [OrgPolicy::findByOrgAndType($org, 3)?->enabled, OrgPolicy::findByOrgAndType($org, 22)?->enabled]);
    }

    public function test_policies_by_invitation_token(): void
    {
        $org = $this->createOrganization();
        $this->putJson("/api/organizations/{$org}/policies/2", ['policy' => ['enabled' => true, 'data' => ['minLength' => 10]]], $this->owner)->assertStatus(200);
        $jwt = $this->app->make(Jwt::class);
        $token = fn (string $orgId): string => $jwt->encode(['nbf' => time(), 'exp' => time() + 60, 'iss' => $jwt->issuer(JwtIssuer::Invite), 'sub' => Random::uuid(),
            'email' => 'new@example.com', 'org_id' => $orgId, 'member_id' => Random::uuid(), 'invited_by_email' => null]);

        $this->get("/api/organizations/{$org}/policies/token?token=".$token($org))->assertStatus(200)->assertJsonPath('data.0.data.minLength', 10);
        $this->get("/api/organizations/{$org}/policies/token?token=".$token(Random::uuid()))
            ->assertStatus(400)->assertJsonPath('message', "Token doesn't match request organization");
        $this->get('/api/organizations/00000000-0000-0000-0000-000000000000/policies/token?token='.$token('00000000-0000-0000-0000-000000000000'))
            ->assertStatus(200)->assertContent('{}');
        // Without a token, the next route answers: its guard first, then no type "token".
        $this->get("/api/organizations/{$org}/policies/token", ['Accept' => 'application/json'])->assertStatus(401);
        $this->get("/api/organizations/{$org}/policies/token", $this->owner)->assertStatus(404);
    }

    private function createOrganization(): string
    {
        $id = $this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $this->owner)->assertStatus(200)->json('id');
        $this->assertIsString($id);

        return $id;
    }

    private function addMember(string $orgId): string
    {
        $this->postJson("/api/organizations/{$orgId}/users/invite", ['emails' => ['member@example.com'], 'groups' => [], 'type' => 2], $this->owner)->assertStatus(200);
        $memberId = Membership::query()->where('user_uuid', $this->memberUser->uuid)->value('uuid');
        $this->assertIsString($memberId);
        $this->postJson("/api/organizations/{$orgId}/users/{$memberId}/confirm", ['key' => '4.member-key'], $this->owner)->assertStatus(200);

        return $memberId;
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
}
