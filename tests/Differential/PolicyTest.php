<?php

namespace Tests\Differential;

use Tests\Attributes\Parity;

/**
 * Organization policies: listing, reading and setting them, what enabling
 * the 2FA and single organization policies does to members, and the
 * policies the invited see through their invitation token.
 */
class PolicyTest extends DifferentialTestCase
{
    #[Parity('route:GET /api/organizations/{org_id}/policies')]
    #[Parity('route:GET /api/organizations/{org_id}/policies/{pol_type}')]
    #[Parity('route:PUT /api/organizations/{org_id}/policies/{pol_type}')]
    #[Parity('route:GET /api/organizations/{org_id}/policies/master-password')]
    #[Parity('route:GET /api/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password')]
    public function test_policies(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$owner] = CipherTest::session($server, 'policies-owner@example.com');
            [$member] = CipherTest::session($server, 'policies-member@example.com');
            [$other] = CipherTest::session($server, 'policies-other@example.com');
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            OrganizationTest::addMember($server, $owner, $org, 'policies-member@example.com');
            OrganizationTest::addMember($server, $owner, $org, 'policies-other@example.com');
            // The other member also owns an organization of their own.
            $server->json('POST', '/api/organizations', [...OrganizationTest::org(), 'name' => '2.own'], $other);
            $policies = "/api/organizations/{$org}/policies";
            $steps = [];

            $steps['list'] = $server->send('GET', $policies, $owner);
            $steps['missing'] = $server->send('GET', "{$policies}/2", $owner);
            $steps['missing account recovery'] = $server->send('GET', "{$policies}/8", $owner);
            $steps['unsupported'] = $server->send('GET', "{$policies}/4", $owner);
            $steps['with a sign and zeros'] = $server->send('GET', "{$policies}/+02", $owner);
            $steps['not a number'] = $server->send('GET', "{$policies}/nope", $owner);
            $steps['too large'] = $server->send('GET', "{$policies}/2147483648", $owner);
            $steps['as member'] = $server->send('GET', "{$policies}/2", $member);

            $steps['set'] = $server->json('PUT', "{$policies}/2", ['policy' => ['enabled' => true, 'data' => ['useUpper' => true, 'minLength' => 12, 'nested' => ['b' => 1, 'a' => []]]]], $owner);
            $steps['set unsupported'] = $server->json('PUT', "{$policies}/4", ['policy' => ['enabled' => true, 'data' => null]], $owner);
            $steps['set not a number'] = $server->json('PUT', "{$policies}/nope", ['policy' => ['enabled' => true]], $owner);
            $steps['set without enabled'] = $server->json('PUT', "{$policies}/2", ['policy' => ['data' => null]], $owner);
            $steps['set without policy'] = $server->json('PUT', "{$policies}/2", ['enabled' => true], $owner);
            $steps['set as member'] = $server->json('PUT', "{$policies}/2", ['policy' => ['enabled' => false]], $member);
            $steps['set again without data'] = $server->json('PUT', "{$policies}/2", ['policy' => ['enabled' => false]], $owner);
            $steps['set send options'] = $server->json('PUT', "{$policies}/7", ['policy' => ['enabled' => true, 'data' => ['disableHideEmail' => true]]], $owner);
            $steps['set account recovery'] = $server->json('PUT', "{$policies}/8", ['policy' => ['enabled' => true, 'data' => ['autoEnrollEnabled' => false]]], $owner);
            $steps['get'] = $server->send('GET', "{$policies}/2", $owner);
            $steps['list after'] = $server->send('GET', $policies, $owner);
            $steps['member sync'] = OrganizationTest::sortedSync($server->send('GET', '/api/sync?excludeDomains=true', $member));

            $steps['master password'] = $server->send('GET', "{$policies}/master-password", $member);
            $steps['master password of another organization'] = $server->send('GET', '/api/organizations/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/policies/master-password', $member);
            $steps['master password for SSO'] = $server->send('GET', '/api/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password');
            $steps['master password for SSO in lower case'] = $server->send('GET', '/api/organizations/00000000-01dc-01dc-01dc-000000000000/policies/master-password', $member);
            $steps['set master password'] = $server->json('PUT', "{$policies}/1", ['policy' => ['enabled' => true, 'data' => ['minComplexity' => 3, 'requireUpper' => true]]], $owner);
            $steps['master password set'] = $server->send('GET', "{$policies}/master-password", $member);

            $steps['enable single organization'] = $server->json('PUT', "{$policies}/3", ['policy' => ['enabled' => true, 'data' => null]], $owner);
            $steps['members after single organization'] = $server->send('GET', "/api/organizations/{$org}/users", $owner);
            $steps['enable two-factor login'] = $server->json('PUT', "{$policies}/0", ['policy' => ['enabled' => true, 'data' => null]], $owner);
            $steps['members after two-factor login'] = $server->send('GET', "/api/organizations/{$org}/users", $owner);
            $steps['restore without two-factor login'] = $server->send('PUT', "/api/organizations/{$org}/users/".self::memberId($server, $owner, $org, 'policies-member@example.com').'/restore', $owner);
            $steps['create another organization'] = $server->json('POST', '/api/organizations', [...OrganizationTest::org(), 'name' => '2.x'], $member);

            return $steps;
        });
    }

    /**
     * Vaultwarden 863395f5: the Fill Assist policy needs the single
     * organization policy and an HTTPS rules URL.
     */
    #[Parity('route:PUT /api/organizations/{org_id}/policies/{pol_type}')]
    public function test_fill_assist_policy(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$owner] = CipherTest::session($server, 'fill-assist-owner@example.com');
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $policies = "/api/organizations/{$org}/policies";
            $put = static fn (int $type, bool $enabled, mixed $data): Exchange => $server->json('PUT', "{$policies}/{$type}",
                ['policy' => ['enabled' => $enabled, 'data' => $data]], $owner);
            $steps = [];

            $steps['without single organization'] = $put(22, true, ['rulesUrl' => 'https://rules.example']);
            $steps['disabled without single organization'] = $put(22, false, ['rulesUrl' => 'not a url']);
            $steps['disabled with bad data'] = $put(22, false, ['rulesUrl' => 5]);
            $steps['enable single organization'] = $put(3, true, null);
            $steps['without data'] = $put(22, true, null);
            $steps['without a url'] = $put(22, true, ['other' => true]);
            $steps['blank url'] = $put(22, true, ['rulesUrl' => " \u{a0}\t"]);
            $steps['string data'] = $put(22, true, 'https://rules.example');
            $steps['number url'] = $put(22, true, ['rulesUrl' => 5]);
            $steps['both spellings'] = $put(22, true, ['rulesUrl' => 'https://a.example', 'RulesUrl' => 'https://b.example']);
            $steps['empty list'] = $put(22, true, []);
            $steps['longer list'] = $put(22, true, ['https://rules.example', 'https://more.example']);
            $steps['not a url'] = $put(22, true, ['rulesUrl' => 'rules']);
            $steps['mail url'] = $put(22, true, ['rulesUrl' => 'mailto:rules@example.com']);
            $steps['ftp url'] = $put(22, true, ['rulesUrl' => 'ftp://rules.example/feed']);
            $steps['http url'] = $put(22, true, ['RulesUrl' => 'http://rules.example']);
            $steps['in a list'] = $put(22, true, ['https://list.example/feed']);
            $steps['enable'] = $put(22, true, ['RulesUrl' => ' https://rules.example/feed?x#y ', 'extra' => 1]);
            $steps['enable again with other data'] = $put(22, true, ['rulesUrl' => 'https://other.example']);
            $steps['disable single organization'] = $put(3, false, null);
            $steps['disable'] = $put(22, false, null);
            $steps['disable single organization after'] = $put(3, false, null);
            $steps['list'] = $server->send('GET', $policies, $owner);

            return $steps;
        });
    }

    #[Parity('route:GET /api/organizations/{org_id}/policies/token')]
    public function test_policies_by_invitation_token(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$owner] = CipherTest::session($server, 'token-policies-owner@example.com');
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $server->json('PUT', "/api/organizations/{$org}/policies/2", ['policy' => ['enabled' => true, 'data' => ['minLength' => 10]]], $owner);
            $invite = fn (string $orgId): string => $this->signedToken('invite', ['nbf' => time() - 10, 'exp' => time() + 3600, 'sub' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
                'email' => 'invited@example.com', 'org_id' => $orgId, 'member_id' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'invited_by_email' => null]);
            $steps = [];

            $steps['list'] = $server->send('GET', "/api/organizations/{$org}/policies/token?token=".$invite($org));
            $steps['for another organization'] = $server->send('GET', "/api/organizations/{$org}/policies/token?token=".$invite('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'));
            $steps['from the admin panel'] = $server->send('GET', '/api/organizations/00000000-0000-0000-0000-000000000000/policies/token?token='.$invite('00000000-0000-0000-0000-000000000000'));
            $steps['expired'] = $server->send('GET', "/api/organizations/{$org}/policies/token?token=".$this->signedToken('invite', ['nbf' => time() - 7200, 'exp' => time() - 3600,
                'sub' => 'x', 'email' => 'x', 'org_id' => $org, 'member_id' => 'x', 'invited_by_email' => null]));
            $steps['of another issuer'] = $server->send('GET', "/api/organizations/{$org}/policies/token?token=".$this->signedToken('delete', ['nbf' => time() - 10, 'exp' => time() + 3600, 'sub' => 'x']));
            $steps['garbage'] = $server->send('GET', "/api/organizations/{$org}/policies/token?token=nope");
            $steps['without token'] = $server->send('GET', "/api/organizations/{$org}/policies/token");
            $steps['invalid organization id'] = $server->send('GET', '/api/organizations/nope/policies/token?token=nope');

            return $steps;
        });
    }

    /**
     * @param  array<string, string>  $owner
     */
    private static function memberId(Server $server, array $owner, string $org, string $email): string
    {
        return OrganizationTest::memberIds($server->send('GET', "/api/organizations/{$org}/users", $owner))[$email];
    }
}
