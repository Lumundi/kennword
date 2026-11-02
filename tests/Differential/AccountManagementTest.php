<?php

namespace Tests\Differential;

use Tests\Attributes\Parity;

/**
 * What users do with their account and devices: the server config, the
 * master password, KDF and keys, the email address, deletion, and logins
 * approved by another device.
 */
class AccountManagementTest extends DifferentialTestCase
{
    #[Parity('route:GET /api/config')]
    #[Parity('route:GET /api/webauthn')]
    #[Parity('route:GET /api/tasks')]
    #[Parity('route:GET /api/hibp/breach')]
    #[Parity('config:EXPERIMENTAL_CLIENT_FEATURE_FLAGS')]
    public function test_config_and_small_routes(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, 'account-config@example.com');
            $steps = [];

            // We name ourselves, as AGENTS.md asks; the rest must match.
            $config = $server->send('GET', '/api/config');
            $body = json_decode($config->body, true);
            $this->assertIsArray($body);
            $this->assertContains(data_get($body, 'server.name'), ['Vaultwarden', 'Kennword']);
            unset($body['server'], $body['gitHash']);
            $steps['config'] = $config->withBody((string) json_encode($body));
            $steps['webauthn'] = $server->send('GET', '/api/webauthn', $auth);
            $steps['webauthn without session'] = $server->send('GET', '/api/webauthn', ['Accept' => 'application/json']);
            $steps['tasks'] = $server->send('GET', '/api/tasks');
            $steps['breaches'] = $server->send('GET', '/api/hibp/breach?username='.rawurlencode('a b&c@example.com'), $auth);
            $steps['breaches without username'] = $server->send('GET', '/api/hibp/breach', $auth);
            $steps['breaches without session'] = $server->send('GET', '/api/hibp/breach?username=x', ['Accept' => 'application/json']);

            return $steps;
        });
    }

    #[Parity('route:GET /api/devices/knowndevice')]
    #[Parity('route:GET /api/devices')]
    #[Parity('route:GET /api/devices/identifier/{device_id}')]
    #[Parity('route:POST /api/devices/identifier/{device_id}/token')]
    #[Parity('route:PUT /api/devices/identifier/{device_id}/token')]
    #[Parity('route:PUT /api/devices/identifier/{device_id}/clear-token')]
    #[Parity('route:POST /api/devices/identifier/{device_id}/clear-token')]
    public function test_devices(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, 'account-devices@example.com');
            $email = rtrim(strtr(base64_encode('account-devices@example.com'), '+/', '-_'), '=');
            $steps = [];

            $steps['devices'] = $server->send('GET', '/api/devices', $auth);
            $steps['device'] = $server->send('GET', '/api/devices/identifier/'.LoginTest::DEVICE, $auth);
            $steps['unknown device'] = $server->send('GET', '/api/devices/identifier/nope', $auth);
            $steps['known device'] = self::knownDevice($server, ['X-Request-Email' => $email, 'X-Device-Identifier' => LoginTest::DEVICE]);
            $steps['known device, padded'] = self::knownDevice($server, ['X-Request-Email' => $email.'==', 'X-Device-Identifier' => LoginTest::DEVICE]);
            $steps['other device'] = self::knownDevice($server, ['X-Request-Email' => $email, 'X-Device-Identifier' => 'nope']);
            $steps['unknown email'] = self::knownDevice($server, ['X-Request-Email' => rtrim(strtr(base64_encode('nobody@example.com'), '+/', '-_'), '='), 'X-Device-Identifier' => LoginTest::DEVICE]);
            $steps['email not base64'] = self::knownDevice($server, ['X-Request-Email' => 'a+b/', 'X-Device-Identifier' => LoginTest::DEVICE]);
            $steps['email not UTF-8'] = self::knownDevice($server, ['X-Request-Email' => '_w', 'X-Device-Identifier' => LoginTest::DEVICE]);
            $steps['without email'] = self::knownDevice($server, ['X-Device-Identifier' => LoginTest::DEVICE]);
            $steps['without device'] = self::knownDevice($server, ['X-Request-Email' => $email]);

            $steps['push token'] = $server->json('PUT', '/api/devices/identifier/whatever/token', ['pushToken' => 'push-token'], $auth);
            $steps['same push token'] = $server->json('POST', '/api/devices/identifier/whatever/token', ['pushToken' => 'push-token'], $auth);
            $steps['push token without body'] = $server->json('PUT', '/api/devices/identifier/whatever/token', [], $auth);
            $steps['clear token'] = $server->send('PUT', '/api/devices/identifier/'.LoginTest::DEVICE.'/clear-token');
            $steps['clear token by POST'] = $server->send('POST', '/api/devices/identifier/'.LoginTest::DEVICE.'/clear-token');
            $steps['devices at last'] = $server->send('GET', '/api/devices', $auth);

            return $steps;
        });
    }

    #[Parity('route:POST /api/accounts/verify-password')]
    #[Parity('route:POST /api/accounts/api-key')]
    #[Parity('route:POST /api/accounts/rotate-api-key')]
    #[Parity('route:POST /api/accounts/password')]
    #[Parity('route:POST /api/accounts/kdf')]
    #[Parity('route:POST /api/accounts/set-password')]
    #[Parity('route:POST /api/accounts/key-management/user-key-id')]
    #[Parity('route:POST /api/accounts/security-stamp')]
    #[Parity('route:POST /api/accounts/password-hint')]
    public function test_password_and_keys(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            $email = 'account-password@example.com';
            [$auth] = CipherTest::session($server, $email);
            $kdf = ['kdf' => 0, 'kdfIterations' => 600000];
            $steps = [];

            $steps['verify a wrong password'] = $server->json('POST', '/api/accounts/verify-password', ['masterPasswordHash' => 'wrong'], $auth);
            $steps['verify the password'] = $server->json('POST', '/api/accounts/verify-password', ['masterPasswordHash' => 'client-hash'], $auth);
            $steps['api key with a wrong password'] = $server->json('POST', '/api/accounts/api-key', ['masterPasswordHash' => 'wrong'], $auth);
            $steps['api key'] = $first = $server->json('POST', '/api/accounts/api-key', ['masterPasswordHash' => 'client-hash'], $auth);
            $again = $server->json('POST', '/api/accounts/api-key', ['masterPasswordHash' => 'client-hash'], $auth);
            $steps['api key again is the same'] = $again->withBody((string) json_encode($again->json('apiKey') === $first->json('apiKey')));
            $rotated = $server->json('POST', '/api/accounts/rotate-api-key', ['masterPasswordHash' => 'client-hash'], $auth);
            $steps['rotated api key'] = $rotated;
            $steps['rotated api key differs'] = $rotated->withBody((string) json_encode($rotated->json('apiKey') !== $first->json('apiKey')));
            $steps['set password when initialized'] = $server->json('POST', '/api/accounts/set-password', [...$kdf, 'key' => '2.key', 'masterPasswordHash' => 'x'], $auth);
            $steps['hint without mail'] = $server->json('POST', '/api/accounts/password-hint', ['email' => $email]);

            $steps['password with a wrong hash'] = $server->json('POST', '/api/accounts/password', ['masterPasswordHash' => 'wrong', 'newMasterPasswordHash' => 'new', 'key' => '2.new'], $auth);
            $steps['password without new data'] = $server->json('POST', '/api/accounts/password', ['masterPasswordHash' => 'client-hash'], $auth);
            $authentication = ['salt' => $email, 'kdf' => $kdf, 'masterPasswordAuthenticationHash' => 'second-hash'];
            $unlock = ['salt' => $email, 'kdf' => $kdf, 'masterKeyWrappedUserKey' => '2.second-key'];
            $steps['password with other KDF settings'] = $server->json('POST', '/api/accounts/password', ['masterPasswordHash' => 'client-hash',
                'authenticationData' => $authentication, 'unlockData' => [...$unlock, 'kdf' => ['kdf' => 0, 'kdfIterations' => 700000]]], $auth);
            $steps['password with another salt'] = $server->json('POST', '/api/accounts/password', ['masterPasswordHash' => 'client-hash',
                'authenticationData' => [...$authentication, 'salt' => 'x@example.com'], 'unlockData' => $unlock], $auth);
            $steps['password'] = $server->json('POST', '/api/accounts/password', ['masterPasswordHash' => 'client-hash', 'masterPasswordHint' => '  my hint ',
                'newMasterPasswordHash' => 'first-hash', 'key' => '2.first-key'], $auth);
            $steps['old session'] = $server->send('GET', '/api/accounts/profile', $auth);
            $steps['old password'] = $server->form('/identity/connect/token', LoginTest::loginFields($email));
            $steps['new password'] = $login = $server->form('/identity/connect/token', LoginTest::loginFields($email, 'first-hash'));
            $auth = ['Authorization' => 'Bearer '.$login->jsonString('access_token'), 'Accept' => 'application/json'];
            $steps['password by authentication and unlock data'] = $server->json('POST', '/api/accounts/password', ['masterPasswordHash' => 'first-hash',
                'authenticationData' => $authentication, 'unlockData' => $unlock], $auth);
            $login = $server->form('/identity/connect/token', LoginTest::loginFields($email, 'second-hash'));
            $steps['second password'] = $login;
            $auth = ['Authorization' => 'Bearer '.$login->jsonString('access_token'), 'Accept' => 'application/json'];

            $argon = ['kdf' => 1, 'kdfIterations' => 3, 'kdfMemory' => 64, 'kdfParallelism' => 4];
            $kdfChange = static fn (array $kdf, string $hash = 'second-hash'): array => ['masterPasswordHash' => $hash,
                'authenticationData' => ['salt' => $email, 'kdf' => $kdf, 'masterPasswordAuthenticationHash' => 'argon-hash'],
                'unlockData' => ['salt' => $email, 'kdf' => $kdf, 'masterKeyWrappedUserKey' => '2.argon-key']];
            $steps['kdf with a wrong password'] = $server->json('POST', '/api/accounts/kdf', $kdfChange($argon, 'wrong'), $auth);
            $steps['kdf with too few iterations'] = $server->json('POST', '/api/accounts/kdf', $kdfChange(['kdf' => 0, 'kdfIterations' => 5000]), $auth);
            $steps['kdf without memory'] = $server->json('POST', '/api/accounts/kdf', $kdfChange(['kdf' => 1, 'kdfIterations' => 3, 'kdfParallelism' => 4]), $auth);
            $steps['kdf with too much memory'] = $server->json('POST', '/api/accounts/kdf', $kdfChange([...$argon, 'kdfMemory' => 2048]), $auth);
            $steps['kdf with too much parallelism'] = $server->json('POST', '/api/accounts/kdf', $kdfChange([...$argon, 'kdfParallelism' => 17]), $auth);
            $steps['kdf'] = $server->json('POST', '/api/accounts/kdf', $kdfChange($argon), $auth);
            $steps['prelogin after kdf'] = $server->json('POST', '/identity/accounts/prelogin', ['email' => $email]);
            $login = $server->form('/identity/connect/token', LoginTest::loginFields($email, 'argon-hash'));
            $steps['login after kdf'] = $login;
            $auth = ['Authorization' => 'Bearer '.$login->jsonString('access_token'), 'Accept' => 'application/json'];

            $steps['user key id'] = $server->json('POST', '/api/accounts/key-management/user-key-id', ['userKeyId' => 'key-id'], $auth);
            $steps['user key id again'] = $server->json('POST', '/api/accounts/key-management/user-key-id', ['userKeyId' => 'other'], $auth);
            $steps['profile'] = $server->send('GET', '/api/accounts/profile', $auth);

            $steps['security stamp with a wrong password'] = $server->json('POST', '/api/accounts/security-stamp', ['masterPasswordHash' => 'wrong'], $auth);
            $steps['security stamp'] = $server->json('POST', '/api/accounts/security-stamp', ['masterPasswordHash' => 'argon-hash'], $auth);
            $steps['session after the stamp'] = $server->send('GET', '/api/accounts/profile', $auth);
            $steps['device after the stamp'] = $server->send('GET', '/api/devices/knowndevice', ['Accept' => 'application/json',
                'X-Request-Email' => rtrim(strtr(base64_encode($email), '+/', '-_'), '='), 'X-Device-Identifier' => LoginTest::DEVICE]);

            return $steps;
        });
    }

    #[Parity('route:POST /api/accounts/key-management/rotate-user-account-keys')]
    public function test_key_rotation(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            $email = 'account-rotation@example.com';
            [$auth, $userId] = CipherTest::session($server, $email);
            $folderId = $server->json('POST', '/api/folders', ['name' => '2.folder'], $auth)->jsonString('id');
            $cipherId = CipherTest::note($server, $auth, $userId, '2.note');
            $sendId = $server->json('POST', '/api/sends', SendTest::text(), $auth)->jsonString('id');
            $cipher = [...CipherTest::cipher($userId, 2, '2.rotated-note'), 'id' => $cipherId, 'secureNote' => ['type' => 0], 'key' => '2.new-cipher-key'];
            $rotation = [
                'accountUnlockData' => [
                    'emergencyAccessUnlockData' => [],
                    'masterPasswordUnlockData' => ['kdfType' => 0, 'kdfIterations' => 600000, 'kdfParallelism' => null, 'kdfMemory' => null,
                        'email' => $email, 'masterKeyAuthenticationHash' => 'rotated-hash', 'masterKeyEncryptedUserKey' => '2.rotated-key'],
                    'organizationAccountRecoveryUnlockData' => [],
                ],
                'accountKeys' => ['userKeyEncryptedAccountPrivateKey' => '2.rotated-private-key', 'accountPublicKey' => 'public-key'],
                'accountData' => [
                    'ciphers' => [$cipher],
                    'folders' => [['id' => $folderId, 'name' => '2.rotated-folder'], ['id' => '', 'name' => '2.null-folder']],
                    'sends' => [[...SendTest::text(['key' => '2.rotated-send-key']), 'id' => $sendId]],
                ],
                'oldMasterKeyAuthenticationHash' => 'client-hash',
            ];
            $steps = [];

            $steps['wrong password'] = $server->json('POST', '/api/accounts/key-management/rotate-user-account-keys', [...$rotation, 'oldMasterKeyAuthenticationHash' => 'x'], $auth);
            $steps['other email'] = $server->json('POST', '/api/accounts/key-management/rotate-user-account-keys', ['accountUnlockData' => [...$rotation['accountUnlockData'],
                'masterPasswordUnlockData' => [...$rotation['accountUnlockData']['masterPasswordUnlockData'], 'email' => 'x@example.com']]] + $rotation, $auth);
            $steps['other key pair'] = $server->json('POST', '/api/accounts/key-management/rotate-user-account-keys', ['accountKeys' => [...$rotation['accountKeys'],
                'accountPublicKey' => 'other']] + $rotation, $auth);
            $steps['missing cipher'] = $server->json('POST', '/api/accounts/key-management/rotate-user-account-keys', [...$rotation, 'accountData' => [...$rotation['accountData'], 'ciphers' => []]], $auth);
            $steps['missing folder'] = $server->json('POST', '/api/accounts/key-management/rotate-user-account-keys', [...$rotation, 'accountData' => [...$rotation['accountData'], 'folders' => []]], $auth);
            $steps['missing send'] = $server->json('POST', '/api/accounts/key-management/rotate-user-account-keys', [...$rotation, 'accountData' => [...$rotation['accountData'], 'sends' => []]], $auth);
            $steps['without account data'] = $server->json('POST', '/api/accounts/key-management/rotate-user-account-keys', ['accountData' => null] + $rotation, $auth);
            $steps['rotate'] = $server->json('POST', '/api/accounts/key-management/rotate-user-account-keys', $rotation, $auth);
            $steps['old session'] = $server->send('GET', '/api/accounts/profile', $auth);
            $steps['login'] = $login = $server->form('/identity/connect/token', LoginTest::loginFields($email, 'rotated-hash'));
            $auth = ['Authorization' => 'Bearer '.$login->jsonString('access_token'), 'Accept' => 'application/json'];
            $steps['sync'] = OrganizationTest::sortedSync($server->send('GET', '/api/sync', $auth));

            return $steps;
        });
    }

    #[Parity('route:POST /api/accounts/email-token')]
    #[Parity('route:POST /api/accounts/email')]
    #[Parity('route:POST /api/accounts/verify-email')]
    #[Parity('route:POST /api/accounts/verify-email-token')]
    #[Parity('route:POST /api/accounts/delete-recover')]
    #[Parity('route:POST /api/accounts/delete-recover-token')]
    #[Parity('template:email/change_email')]
    #[Parity('template:email/change_email.html')]
    #[Parity('template:email/change_email_existing*')]
    #[Parity('template:email/verify_email*')]
    #[Parity('template:email/delete_account*')]
    #[Parity('template:email/pw_hint_none*')]
    public function test_email_change_and_deletion_by_mail(): void
    {
        $this->assertSameMailFlows(function (Server $server): array {
            $email = 'account-mail@example.com';
            [$auth, $userId] = CipherTest::session($server, $email);
            CipherTest::session($server, 'account-taken@example.com');
            $steps = [];

            $steps['hint'] = $server->json('POST', '/api/accounts/password-hint', ['email' => $email]);
            $steps['hint mail'] = $server->mail($email)->exchange();
            $steps['hint for nobody'] = $server->json('POST', '/api/accounts/password-hint', ['email' => 'account-nobody@example.com']);

            $steps['token with a wrong password'] = $server->json('POST', '/api/accounts/email-token', ['masterPasswordHash' => 'x', 'newEmail' => 'account-new@example.com'], $auth);
            $steps['token for a taken address'] = $server->json('POST', '/api/accounts/email-token', ['masterPasswordHash' => 'client-hash', 'newEmail' => 'account-taken@example.com'], $auth);
            $steps['taken address mail'] = $server->mail('account-taken@example.com')->exchange();
            $steps['token'] = $server->json('POST', '/api/accounts/email-token', ['masterPasswordHash' => 'client-hash', 'newEmail' => 'account-new@example.com'], $auth);
            [$steps['token mail'], $code] = self::codeMail($server, 'account-new@example.com');
            $change = ['masterPasswordHash' => 'client-hash', 'newEmail' => 'account-new@example.com', 'key' => '2.new-key', 'newMasterPasswordHash' => 'new-hash', 'token' => $code];
            $steps['change to another address'] = $server->json('POST', '/api/accounts/email', [...$change, 'newEmail' => 'account-other@example.com'], $auth);
            $steps['change with a wrong code'] = $server->json('POST', '/api/accounts/email', [...$change, 'token' => '000000'], $auth);
            $steps['change to a taken address'] = $server->json('POST', '/api/accounts/email', [...$change, 'newEmail' => 'account-taken@example.com'], $auth);
            $steps['change'] = $server->json('POST', '/api/accounts/email', $change, $auth);
            $steps['change again'] = $server->json('POST', '/api/accounts/email', $change, $auth);
            $steps['login with the new address'] = $login = $server->form('/identity/connect/token', LoginTest::loginFields('account-new@example.com', 'new-hash'));
            $auth = ['Authorization' => 'Bearer '.$login->jsonString('access_token'), 'Accept' => 'application/json'];
            $steps['profile'] = $server->send('GET', '/api/accounts/profile', $auth);

            $steps['verify'] = $server->send('POST', '/api/accounts/verify-email', $auth);
            $steps['verify mail'] = $server->mail('account-new@example.com')->exchange();
            $token = $server->mailedToken('account-new@example.com');
            $steps['verify with a bad token'] = $server->json('POST', '/api/accounts/verify-email-token', ['userId' => $userId, 'token' => 'nope']);
            $steps['verify for another user'] = $server->json('POST', '/api/accounts/verify-email-token', ['userId' => '00000000-0000-4000-8000-000000000000', 'token' => $token]);
            $steps['verify with the token'] = $server->json('POST', '/api/accounts/verify-email-token', ['userId' => $userId, 'token' => $token]);

            $steps['delete recover for nobody'] = $server->json('POST', '/api/accounts/delete-recover', ['email' => 'account-nobody@example.com']);
            $steps['delete recover'] = $server->json('POST', '/api/accounts/delete-recover', ['email' => 'account-new@example.com']);
            $steps['delete mail'] = $server->mail('account-new@example.com')->exchange();
            $token = $server->mailedToken('account-new@example.com');
            $steps['delete with a bad token'] = $server->json('POST', '/api/accounts/delete-recover-token', ['userId' => $userId, 'token' => 'nope']);
            $steps['delete with the token'] = $server->json('POST', '/api/accounts/delete-recover-token', ['userId' => $userId, 'token' => $token]);
            $steps['login after deletion'] = $server->form('/identity/connect/token', LoginTest::loginFields('account-new@example.com', 'new-hash'));

            return $steps;
        });
    }

    #[Parity('route:POST /api/accounts/delete')]
    #[Parity('route:DELETE /api/accounts')]
    public function test_account_deletion(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, 'account-delete@example.com');
            [$other] = CipherTest::session($server, 'account-delete-too@example.com');
            $steps = [];

            $steps['delete with a wrong password'] = $server->json('POST', '/api/accounts/delete', ['masterPasswordHash' => 'wrong'], $auth);
            $steps['delete without validation'] = $server->json('DELETE', '/api/accounts', [], $auth);
            $steps['delete'] = $server->json('POST', '/api/accounts/delete', ['masterPasswordHash' => 'client-hash'], $auth);
            $steps['login after deletion'] = $server->form('/identity/connect/token', LoginTest::loginFields('account-delete@example.com'));
            $steps['verify email without mail'] = $server->send('POST', '/api/accounts/verify-email', $other);
            $steps['recover without mail'] = $server->json('POST', '/api/accounts/delete-recover', ['email' => 'account-delete@example.com']);
            $steps['delete by DELETE'] = $server->json('DELETE', '/api/accounts', ['masterPasswordHash' => 'client-hash'], $other);

            return $steps;
        });
    }

    #[Parity('route:POST /api/auth-requests')]
    #[Parity('route:GET /api/auth-requests/{auth_request_id}')]
    #[Parity('route:PUT /api/auth-requests/{auth_request_id}')]
    #[Parity('route:GET /api/auth-requests/{auth_request_id}/response')]
    #[Parity('route:GET /api/auth-requests')]
    #[Parity('route:GET /api/auth-requests/pending')]
    public function test_login_with_a_device(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            $email = 'account-auth-request@example.com';
            [$auth] = CipherTest::session($server, $email);
            // The new device must have logged in once; it now asks the first one for the key.
            $newDevice = '0d8f2c1e-3b4a-4c5d-9e6f-7a8b9c0d1e2f';
            $newLogin = ['grant_type' => 'password', 'username' => $email, 'scope' => 'api offline_access', 'client_id' => 'web',
                'device_identifier' => $newDevice, 'device_name' => 'firefox', 'device_type' => '10'];
            $server->form('/identity/connect/token', [...$newLogin, 'password' => 'client-hash']);
            $asking = ['Accept' => 'application/json', 'Device-Type' => '10'];
            $request = ['accessCode' => 'access-code', 'deviceIdentifier' => $newDevice, 'email' => $email, 'publicKey' => 'device-public-key', 'type' => 0];
            $steps = [];

            $steps['ask for an unknown email'] = $server->json('POST', '/api/auth-requests', [...$request, 'email' => 'nobody@example.com'], $asking);
            $steps['ask with another device type'] = $server->json('POST', '/api/auth-requests', $request, ['Accept' => 'application/json', 'Device-Type' => '9']);
            $steps['ask'] = $asked = $server->json('POST', '/api/auth-requests', $request, $asking);
            $id = $asked->jsonString('id');
            $steps['pending'] = $server->send('GET', '/api/auth-requests/pending', $auth);
            $steps['all'] = $server->send('GET', '/api/auth-requests', $auth);
            $steps['devices'] = $server->send('GET', '/api/devices', $auth);
            $steps['request'] = $server->send('GET', "/api/auth-requests/{$id}", $auth);
            $steps['unknown request'] = $server->send('GET', '/api/auth-requests/00000000-0000-4000-8000-000000000000', $auth);
            $steps['response before approval'] = $server->send('GET', "/api/auth-requests/{$id}/response?code=access-code", $asking);
            $steps['response with a wrong code'] = $server->send('GET', "/api/auth-requests/{$id}/response?code=nope", $asking);
            $steps['response without code'] = $server->send('GET', "/api/auth-requests/{$id}/response", $asking);
            $steps['login before approval'] = $server->form('/identity/connect/token', [...$newLogin, 'password' => 'access-code', 'authrequest' => $id]);

            $answer = ['deviceIdentifier' => LoginTest::DEVICE, 'key' => '4.encrypted-user-key', 'masterPasswordHash' => null, 'requestApproved' => true];
            $steps['approve from another device'] = $server->json('PUT', "/api/auth-requests/{$id}", [...$answer, 'deviceIdentifier' => $newDevice], $auth);
            $steps['approve'] = $server->json('PUT', "/api/auth-requests/{$id}", $answer, $auth);
            $steps['approve again'] = $server->json('PUT', "/api/auth-requests/{$id}", $answer, $auth);
            $steps['response'] = $server->send('GET', "/api/auth-requests/{$id}/response?code=access-code", $asking);
            $steps['pending after approval'] = $server->send('GET', '/api/auth-requests/pending', $auth);
            $steps['login with a wrong code'] = $server->form('/identity/connect/token', [...$newLogin, 'password' => 'nope', 'authrequest' => $id]);
            $steps['login with the request'] = $server->form('/identity/connect/token', [...$newLogin, 'password' => 'access-code', 'authrequest' => $id]);
            $steps['login with the request again'] = $server->form('/identity/connect/token', [...$newLogin, 'password' => 'access-code', 'authrequest' => $id]);
            $steps['login with an unknown request'] = $server->form('/identity/connect/token', [...$newLogin, 'password' => 'access-code',
                'authrequest' => '00000000-0000-4000-8000-000000000000']);

            $rejected = $server->json('POST', '/api/auth-requests', $request, $asking)->jsonString('id');
            $steps['reject'] = $server->json('PUT', "/api/auth-requests/{$rejected}", [...$answer, 'requestApproved' => false], $auth);
            $steps['rejected request'] = $server->send('GET', "/api/auth-requests/{$rejected}", $auth);

            return $steps;
        });
    }

    /**
     * GET /api/devices/knowndevice with the headers.
     *
     * @param  array<string, string>  $headers
     */
    private static function knownDevice(Server $server, array $headers): Exchange
    {
        return $server->send('GET', '/api/devices/knowndevice', ['Accept' => 'application/json', ...$headers]);
    }

    /**
     * The last mail to the address with its six-digit code, which is replaced by a placeholder.
     *
     * @return array{Exchange, string}
     */
    private static function codeMail(Server $server, string $to): array
    {
        $mail = $server->mail($to);
        if (preg_match('/\b(\d{6})\b/', $mail->text, $match) !== 1) {
            throw new \RuntimeException("No code in the mail to {$to}.");
        }
        $exchange = $mail->exchange();

        return [$exchange->withBody(str_replace($match[1], '<code>', $exchange->body)), $match[1]];
    }
}
