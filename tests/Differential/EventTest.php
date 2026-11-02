<?php

namespace Tests\Differential;

use Tests\Attributes\Parity;

/**
 * The organization event log: what the server logs (on the pair of servers
 * with ORG_EVENTS_ENABLED), what the clients may add, and the empty lists
 * without events.
 */
class EventTest extends DifferentialTestCase
{
    private const string RANGE = 'start=2000-01-01T00:00:00.000Z&end=2100-01-01T00:00:00.000Z';

    #[Parity('config:ORG_EVENTS_ENABLED')]
    #[Parity('route:GET /api/organizations/{org_id}/events')]
    #[Parity('route:GET /api/ciphers/{cipher_id}/events')]
    #[Parity('route:GET /api/organizations/{org_id}/users/{member_id}/events')]
    #[Parity('route:POST /events/collect')]
    public function test_events(): void
    {
        $this->assertSameFlowsOn((string) getenv('VW_FEATURES_REFERENCE_URL'), (string) getenv('VW_FEATURES_SUBJECT_URL'), function (Server $server): array {
            [$owner, $ownerUserId] = CipherTest::session($server, 'events-owner@example.com');
            [$member] = CipherTest::session($server, 'events-member@example.com');
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $range = self::RANGE;
            $steps = [];

            // What the server logs.
            $server->json('PUT', "/api/organizations/{$org}", ['billingEmail' => 'billing@example.com', 'name' => '2.renamed'], $owner);
            $collection = $server->json('POST', "/api/organizations/{$org}/collections", ['name' => '2.second', 'groups' => [], 'users' => []], $owner)->jsonString('id');
            $memberId = OrganizationTest::addMember($server, $owner, $org, 'events-member@example.com');
            $server->json('PUT', "/api/organizations/{$org}/users/{$memberId}", ['type' => 2, 'collections' => [['id' => $collection, 'readOnly' => false, 'hidePasswords' => false, 'manage' => false]]], $owner);
            $cipher = $server->json('POST', '/api/ciphers/create', ['cipher' => OrganizationTest::note($ownerUserId, '2.note', ['organizationId' => $org]),
                'collectionIds' => [$collection]], $owner)->jsonString('id');
            $server->json('PUT', "/api/ciphers/{$cipher}", OrganizationTest::note($ownerUserId, '2.changed', ['organizationId' => $org]), $owner);
            $server->send('PUT', "/api/ciphers/{$cipher}/delete", $owner);
            $server->send('PUT', "/api/ciphers/{$cipher}/restore", $owner);
            $server->json('PUT', "/api/organizations/{$org}/policies/2", ['policy' => ['enabled' => true, 'data' => null]], $owner);
            $group = $server->json('POST', "/api/organizations/{$org}/groups", ['name' => 'Group', 'collections' => [], 'users' => [$memberId]], $owner)->jsonString('id');
            $server->send('DELETE', "/api/organizations/{$org}/groups/{$group}", $owner);
            $server->send('PUT', "/api/organizations/{$org}/users/{$memberId}/revoke", $owner);
            $server->send('PUT', "/api/organizations/{$org}/users/{$memberId}/restore", $owner);
            // A failed login of a known user.
            $server->form('/identity/connect/token', ['grant_type' => 'password', 'username' => 'events-member@example.com', 'password' => 'wrong',
                'scope' => 'api offline_access', 'client_id' => 'web', 'deviceType' => '10', 'deviceIdentifier' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'deviceName' => 'firefox'],
                ['Device-Type' => '10']);

            // Vaultwarden 79ee29d5: revocations by a policy have events of their own.
            [$other] = CipherTest::session($server, 'events-other@example.com');
            $server->json('POST', '/api/organizations', [...OrganizationTest::org(), 'name' => '2.own'], $other);
            $twoFactorOrg = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $singleOrg = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            OrganizationTest::addMember($server, $owner, $twoFactorOrg, 'events-other@example.com');
            OrganizationTest::addMember($server, $owner, $singleOrg, 'events-other@example.com');
            $server->json('PUT', "/api/organizations/{$twoFactorOrg}/policies/0", ['policy' => ['enabled' => true, 'data' => null]], $owner);
            $server->json('PUT', "/api/organizations/{$singleOrg}/policies/3", ['policy' => ['enabled' => true, 'data' => null]], $owner);
            $steps['two-factor policy events'] = $server->send('GET', "/api/organizations/{$twoFactorOrg}/events?{$range}", $owner);
            $steps['single organization policy events'] = $server->send('GET', "/api/organizations/{$singleOrg}/events?{$range}", $owner);

            $steps['organization events'] = $server->send('GET', "/api/organizations/{$org}/events?{$range}", $owner);
            $steps['member events'] = $server->send('GET', "/api/organizations/{$org}/users/{$memberId}/events?{$range}", $owner);
            $steps['cipher events'] = $server->send('GET', "/api/ciphers/{$cipher}/events?{$range}", $owner);
            $steps['cipher events as member'] = $server->send('GET', "/api/ciphers/{$cipher}/events?{$range}", $member);
            $steps['events as member'] = $server->send('GET', "/api/organizations/{$org}/events?{$range}", $member);
            $steps['invalid start'] = $server->send('GET', "/api/organizations/{$org}/events?start=yesterday&end=2100-01-01T00:00:00Z", $owner);
            $steps['invalid end'] = $server->send('GET', "/api/organizations/{$org}/events?start=2000-01-01T00:00:00Z&end=tomorrow", $owner);
            $steps['without range'] = $server->send('GET', "/api/organizations/{$org}/events", $owner);
            $steps['an empty range'] = $server->send('GET', "/api/organizations/{$org}/events?start=2000-01-01T00:00:00Z&end=2000-01-02T00:00:00Z", $owner);

            // What the clients add: only what they may, for what they reach. Their date
            // comes first in the lists, whatever the timing of either server.
            $now = '2099-01-01T00:00:00.000Z';
            $steps['collect'] = $server->json('POST', '/events/collect', [
                ['type' => 1107, 'cipherId' => $cipher, 'date' => '2099-01-01T00:00:01.000Z'],
                ['type' => 1111, 'cipherId' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'date' => '2099-01-01T00:00:02.000Z'],
                ['type' => 1602, 'organizationId' => $org, 'date' => '2099-01-01T00:00:03.000Z'],
                ['type' => 1602, 'organizationId' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'date' => '2099-01-01T00:00:04.000Z'],
                ['type' => 1007, 'date' => '2099-01-01T00:00:05+01:00'],
                ['type' => 1522, 'organizationId' => $org, 'date' => '2099-01-01T00:00:06.123456Z'],
                ['type' => 1500, 'organizationId' => $org, 'date' => '2099-01-01T00:00:07.000Z'],
                ['type' => 1100, 'cipherId' => $cipher, 'date' => '2099-01-01T00:00:08.000Z'],
                ['type' => 1133, 'cipherId' => $cipher, 'date' => '2099-01-01T00:00:09.000Z'],
                ['type' => 1134, 'cipherId' => $cipher, 'date' => '2099-01-01T00:00:10.000Z'],
            ], $member);
            $steps['collect with a bad date'] = $server->json('POST', '/events/collect', [['type' => 1107, 'cipherId' => $cipher, 'date' => 'now']], $member);
            $steps['collect without a type'] = $server->json('POST', '/events/collect', [['date' => $now]], $member);
            $steps['collect an object'] = $server->json('POST', '/events/collect', ['type' => 1107, 'date' => $now], $member);
            $steps['collect as text'] = $server->send('POST', '/events/collect', [...$member, 'Content-Type' => 'text/plain'], '[]');
            $steps['collect without login'] = $server->json('POST', '/events/collect', []);
            $steps['events after collecting'] = $server->send('GET', "/api/organizations/{$org}/events?{$range}", $owner);

            // A full page continues with the date of its last event.
            $server->json('POST', '/events/collect', array_fill(0, 31, ['type' => 1107, 'cipherId' => $cipher, 'date' => $now]), $owner);
            $steps['first page'] = $first = $server->send('GET', "/api/ciphers/{$cipher}/events?{$range}", $owner);
            $token = $first->jsonString('continuationToken');
            $steps['next page'] = $server->send('GET', "/api/ciphers/{$cipher}/events?{$range}&continuationToken=".rawurlencode($token), $owner);
            $steps['repeated tokens'] = $server->send('GET', "/api/ciphers/{$cipher}/events?{$range}&continuationToken=x&continuationToken=y", $owner);

            return $steps;
        });
    }

    public function test_events_disabled(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$owner, $ownerUserId] = CipherTest::session($server, 'noevents-owner@example.com');
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $cipher = $server->json('POST', '/api/ciphers/create', ['cipher' => OrganizationTest::note($ownerUserId, '2.note', ['organizationId' => $org]),
                'collectionIds' => []], $owner)->jsonString('id');
            $range = self::RANGE;
            $steps = [];

            $steps['organization events'] = $server->send('GET', "/api/organizations/{$org}/events?{$range}", $owner);
            $steps['cipher events'] = $server->send('GET', "/api/ciphers/{$cipher}/events?{$range}", $owner);
            $steps['invalid start'] = $server->send('GET', "/api/organizations/{$org}/events?start=yesterday&end=x", $owner);
            $steps['collect'] = $server->json('POST', '/events/collect', [['type' => 1107, 'cipherId' => $cipher, 'date' => 'not a date']], $owner);

            return $steps;
        });
    }
}
