<?php

namespace Tests\Differential;

use Tests\Attributes\Parity;

/**
 * Organization API keys, the login with them and the directory import of
 * the public API they open.
 */
class ApiKeyTest extends DifferentialTestCase
{
    #[Parity('route:POST /api/organizations/{org_id}/api-key')]
    #[Parity('route:POST /api/organizations/{org_id}/rotate-api-key')]
    public function test_api_keys(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$owner] = CipherTest::session($server, 'apikey-owner@example.com');
            [$admin] = CipherTest::session($server, 'apikey-admin@example.com');
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $adminId = OrganizationTest::addMember($server, $owner, $org, 'apikey-admin@example.com');
            $server->json('PUT', "/api/organizations/{$org}/users/{$adminId}", ['type' => 1, 'collections' => []], $owner);
            $steps = [];

            $steps['with a wrong password'] = $server->json('POST', "/api/organizations/{$org}/api-key", ['masterPasswordHash' => 'wrong'], $owner);
            $steps['without password'] = $server->json('POST', "/api/organizations/{$org}/api-key", [], $owner);
            $steps['as admin'] = $server->json('POST', "/api/organizations/{$org}/api-key", ['masterPasswordHash' => 'client-hash'], $admin);
            $steps['create'] = $created = $server->json('POST', "/api/organizations/{$org}/api-key", ['masterPasswordHash' => 'client-hash'], $owner);
            $key = $created->jsonString('apiKey');
            $steps['again'] = $again = $server->json('POST', "/api/organizations/{$org}/api-key", ['MasterPasswordHash' => 'client-hash'], $owner);
            $steps['the same'] = new Exchange(200, [], json_encode($again->jsonString('apiKey') === $key) ?: '');
            $steps['rotate'] = $rotated = $server->json('POST', "/api/organizations/{$org}/rotate-api-key", ['masterPasswordHash' => 'client-hash'], $owner);
            $steps['rotated'] = new Exchange(200, [], json_encode($rotated->jsonString('apiKey') !== $key) ?: '');

            return $steps;
        });
    }

    #[Parity('route:POST /api/public/organization/import')]
    public function test_login_and_directory_import(): void
    {
        $this->assertSameFlows(fn (Server $server): array => $this->directoryFlow($server, 'directory'));
    }

    public function test_directory_import_with_groups(): void
    {
        $this->assertSameFlowsOn((string) getenv('VW_FEATURES_REFERENCE_URL'), (string) getenv('VW_FEATURES_SUBJECT_URL'),
            fn (Server $server): array => $this->directoryFlow($server, 'groups-directory'));
    }

    /**
     * @return array<string, Exchange>
     */
    private function directoryFlow(Server $server, string $prefix): array
    {
        [$owner] = CipherTest::session($server, "{$prefix}-owner@example.com");
        [$member] = CipherTest::session($server, "{$prefix}-member@example.com");
        CipherTest::session($server, "{$prefix}-known@example.com");
        $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
        $memberId = OrganizationTest::addMember($server, $owner, $org, "{$prefix}-member@example.com");
        $key = $server->json('POST', "/api/organizations/{$org}/api-key", ['masterPasswordHash' => 'client-hash'], $owner)->jsonString('apiKey');
        $login = ['grant_type' => 'client_credentials', 'client_id' => "organization.{$org}", 'client_secret' => $key, 'scope' => 'api.organization'];
        $steps = [];

        $steps['login'] = $token = $server->form('/identity/connect/token', $login);
        $steps['login with a wrong secret'] = $server->form('/identity/connect/token', [...$login, 'client_secret' => 'wrong']);
        $steps['login to an unknown organization'] = $server->form('/identity/connect/token', [...$login, 'client_id' => 'organization.aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee']);
        $steps['login with a malformed client id'] = $server->form('/identity/connect/token', [...$login, 'client_id' => $org]);
        $steps['login with another scope'] = $server->form('/identity/connect/token', [...$login, 'scope' => 'api.other']);
        $public = ['Authorization' => 'Bearer '.$token->jsonString('access_token')];

        $import = static fn (array $members, array $groups = [], bool $overwrite = false): array => ['members' => $members, 'groups' => $groups, 'overwriteExisting' => $overwrite];
        $steps['import without token'] = $server->json('POST', '/api/public/organization/import', $import([]));
        $steps['import with a user token'] = $server->json('POST', '/api/public/organization/import', $import([]), $owner);
        $steps['import a bad body'] = $server->json('POST', '/api/public/organization/import', ['members' => []], $public);
        $steps['import'] = $server->json('POST', '/api/public/organization/import', $import([
            ['email' => "{$prefix}-member@example.com", 'externalId' => 'ext-member', 'deleted' => false],
            ['email' => strtoupper("{$prefix}-known@example.com"), 'externalId' => 'ext-known', 'deleted' => false],
            ['email' => "{$prefix}-new@example.com", 'externalId' => 'ext-new', 'deleted' => false],
            ['email' => "{$prefix}-gone@example.com", 'externalId' => 'ext-gone', 'deleted' => true],
        ], [['name' => 'Staff', 'externalId' => 'grp-staff', 'memberExternalIds' => ['ext-member', 'ext-new', 'ext-unknown']]]), $public);
        $steps['members after the import'] = $server->send('GET', "/api/organizations/{$org}/users?includeGroups=true", $owner);
        $steps['groups after the import'] = $server->send('GET', "/api/organizations/{$org}/groups/details", $owner);

        $steps['revoke through the import'] = $server->json('POST', '/api/public/organization/import', $import([
            ['email' => "{$prefix}-member@example.com", 'externalId' => 'ext-member-2', 'deleted' => true],
            ['email' => "{$prefix}-owner@example.com", 'externalId' => 'ext-owner', 'deleted' => true],
        ], [['name' => 'Renamed', 'externalId' => 'grp-staff', 'memberExternalIds' => []]]), $public);
        $steps['member after the revocation'] = $server->send('GET', "/api/organizations/{$org}/users/{$memberId}?includeGroups=true", $owner);
        $steps['restore through the import'] = $server->json('POST', '/api/public/organization/import', $import([
            ['email' => "{$prefix}-member@example.com", 'externalId' => 'ext-member-2', 'deleted' => false],
        ]), $public);
        $steps['member after the restoration'] = $server->send('GET', "/api/organizations/{$org}/users/{$memberId}", $owner);
        $steps['overwrite'] = $server->json('POST', '/api/public/organization/import', $import([
            ['email' => "{$prefix}-member@example.com", 'externalId' => 'ext-member-2', 'deleted' => false],
        ], [], true), $public);
        $steps['members after the overwrite'] = $server->send('GET', "/api/organizations/{$org}/users", $owner);
        $steps['member profile'] = $server->send('GET', '/api/accounts/profile', $member);

        $rotated = $server->json('POST', "/api/organizations/{$org}/rotate-api-key", ['masterPasswordHash' => 'client-hash'], $owner)->jsonString('apiKey');
        // The old key's token is left out: Kennword refuses it after the rotation, Vaultwarden takes it until
        // it expires (docs/configuration.md). The new key's token works on both.
        $steps['login with the old secret'] = $server->form('/identity/connect/token', $login);
        $steps['login with the new secret'] = $renewed = $server->form('/identity/connect/token', [...$login, 'client_secret' => $rotated]);
        $steps['import with the new token'] = $server->json('POST', '/api/public/organization/import', $import([]),
            ['Authorization' => 'Bearer '.$renewed->jsonString('access_token')]);

        return $steps;
    }
}
