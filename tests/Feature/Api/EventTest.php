<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Device;
use App\Models\Event;
use App\Models\Membership;
use App\Models\User;
use App\Support\Random;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * The organization event log with ORG_EVENTS_ENABLED (src/api/core/events.rs).
 */
class EventTest extends TestCase
{
    use UsesVaultwardenDatabase;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000', 'ORG_EVENTS_ENABLED' => 'true'];
    }

    public function test_events_are_logged_and_listed(): void
    {
        $this->useDatabase('sqlite');
        $owner = User::new('owner@example.com');
        $owner->setPassword('hash', 'user-key', false, null);
        $owner->save();
        $device = Device::new(Random::uuid(), $owner->uuid, 'cli', 8);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $auth = ['Authorization' => 'Bearer '.LoginClaims::default($device, $owner, AuthMethod::Password, 'cli', $jwt)->token($jwt)];

        $org = $this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $auth)->json('id');
        $this->assertIsString($org);
        $collection = $this->postJson("/api/organizations/{$org}/collections", ['name' => '2.second', 'groups' => [], 'users' => []], $auth)->json('id');
        $this->assertIsString($collection);
        $cipher = $this->postJson('/api/ciphers/create', ['cipher' => ['type' => 2, 'name' => '2.note', 'encryptedFor' => $owner->uuid, 'secureNote' => ['type' => 0],
            'organizationId' => $org], 'collectionIds' => [$collection]], $auth)->json('id');
        $this->assertIsString($cipher);
        $this->put("/api/ciphers/{$cipher}/delete", [], $auth)->assertStatus(200);

        $range = 'start=2000-01-01T00:00:00Z&end=2100-01-01T00:00:00Z';
        $events = $this->get("/api/organizations/{$org}/events?{$range}", $auth)->assertStatus(200)->assertJsonPath('continuationToken', null);
        $this->assertSame([Event::CIPHER_SOFT_DELETED, Event::CIPHER_CREATED, Event::COLLECTION_CREATED], array_column((array) $events->json('data'), 'type'));
        $events->assertJsonPath('data.0.cipherId', $cipher)->assertJsonPath('data.0.actingUserId', $owner->uuid)->assertJsonPath('data.0.deviceType', 8);
        $this->get("/api/organizations/{$org}/events?start=nope&end=x", $auth)->assertStatus(400)->assertJsonPath('message', 'Invalid start date');
        $this->get("/api/organizations/{$org}/events", $auth)->assertStatus(404);

        // Clients log only some events, for ciphers they reach.
        $date = gmdate('Y-m-d\TH:i:s\Z');
        $this->call('POST', '/events/collect', server: ['CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => $auth['Authorization']],
            content: (string) json_encode([['type' => 1107, 'cipherId' => $cipher, 'date' => $date], ['type' => 1100, 'cipherId' => $cipher, 'date' => $date],
                ...array_fill(0, 29, ['type' => 1111, 'cipherId' => $cipher, 'date' => $date])]))->assertStatus(200);
        $this->call('POST', '/events/collect', server: ['CONTENT_TYPE' => 'text/plain', 'HTTP_AUTHORIZATION' => $auth['Authorization']], content: '[]')->assertStatus(404);
        $page = $this->get("/api/ciphers/{$cipher}/events?{$range}", $auth)->assertJsonCount(30, 'data');
        $this->assertNotNull($page->json('continuationToken'));
        $this->assertSame(0, Event::query()->where('event_type', 1100)->where('device_type', 8)->whereNull('act_user_uuid')->count());

        // Vaultwarden 79ee29d5: HTTP auth released (1133), not what follows.
        $this->call('POST', '/events/collect', server: ['CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => $auth['Authorization']],
            content: (string) json_encode([['type' => 1133, 'cipherId' => $cipher, 'date' => $date], ['type' => 1134, 'cipherId' => $cipher, 'date' => $date]]))->assertStatus(200);
        $this->assertSame([1, 0], [Event::query()->where('event_type', Event::CIPHER_CLIENT_HTTP_AUTH_RELEASED)->count(), Event::query()->where('event_type', 1134)->count()]);
    }

    public function test_revocations_by_policy_have_events_of_their_own(): void
    {
        $this->useDatabase('sqlite');
        [$owner, $auth] = $this->account('owner@example.com');
        [$member, $memberAuth] = $this->account('member@example.com');
        $create = fn (array $session): string => $this->string($this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $session)->assertStatus(200)->json('id'));
        $create($memberAuth);
        $twoFactorOrg = $create($auth);
        $singleOrg = $create($auth);
        foreach ([$twoFactorOrg, $singleOrg] as $org) {
            $this->postJson("/api/organizations/{$org}/users/invite", ['emails' => ['member@example.com'], 'groups' => [], 'type' => 2], $auth)->assertStatus(200);
            $memberId = $this->string(Membership::query()->where('org_uuid', $org)->where('user_uuid', $member->uuid)->value('uuid'));
            $this->postJson("/api/organizations/{$org}/users/{$memberId}/confirm", ['key' => '4.member-key'], $auth)->assertStatus(200);
        }

        $this->putJson("/api/organizations/{$twoFactorOrg}/policies/0", ['policy' => ['enabled' => true, 'data' => null]], $auth)->assertStatus(200);
        $this->putJson("/api/organizations/{$singleOrg}/policies/3", ['policy' => ['enabled' => true, 'data' => null]], $auth)->assertStatus(200);

        $types = fn (string $org): array => Event::query()->where('org_uuid', $org)->where('act_user_uuid', $owner->uuid)->pluck('event_type')->all();
        $this->assertContains(Event::ORGANIZATION_USER_REVOKED_TWO_FACTOR_NON_COMPLIANCE, $types($twoFactorOrg));
        $this->assertContains(Event::ORGANIZATION_USER_REVOKED_SINGLE_ORGANIZATION_NON_COMPLIANCE, $types($singleOrg));
        $this->assertNotContains(Event::ORGANIZATION_USER_REVOKED, [...$types($twoFactorOrg), ...$types($singleOrg)]);
        $this->assertNotContains(Event::ORGANIZATION_USER_REMOVED, $types($singleOrg));
    }

    /**
     * @return array{User, array<string, string>}
     */
    private function account(string $email): array
    {
        $user = User::new($email);
        $user->setPassword('hash', 'user-key', false, null);
        $user->save();
        $device = Device::new(Random::uuid(), $user->uuid, 'cli', 8);
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
