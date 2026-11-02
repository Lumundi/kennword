<?php

namespace Tests\Feature\Notifications;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Device;
use App\Models\User;
use App\Support\Random;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesFakeServices;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * src/api/push.rs against the fake push relay of fake-services.php.
 */
class PushTest extends TestCase
{
    use UsesFakeServices;
    use UsesVaultwardenDatabase;

    private const string INSTALLATION = '4bdb5a5d-7a8e-4c47-8c1e-6b1a0b3f2c9d';

    private string $relay = '';

    private User $user;

    private Device $phone;

    /**
     * @var array<string, string>
     */
    private array $auth;

    protected function vaultwardenEnvironment(): array
    {
        // A relay of its own for every test.
        $this->relay = '/relay/'.bin2hex(random_bytes(4));
        $relay = 'https://'.self::$servicesHost.$this->relay;

        return ['PASSWORD_ITERATIONS' => '100000', 'SSL_CERT_FILE' => self::$servicesFolder.'/ca.pem', 'HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS' => 'false',
            'PUSH_ENABLED' => 'true', 'PUSH_INSTALLATION_ID' => self::INSTALLATION, 'PUSH_INSTALLATION_KEY' => self::installationKey(),
            'PUSH_RELAY_URI' => $relay, 'PUSH_IDENTITY_URI' => "{$relay}/identity"];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');

        $this->user = User::new('push@example.com');
        $this->user->setPassword('client-hash', 'user-key', resetSecurityStamp: false, allowNextRoute: null);
        $this->user->save();
        // An Android phone.
        $this->phone = Device::new(Random::uuid(), $this->user->uuid, 'Pixel', 0);
        $this->phone->save();
        $jwt = $this->app->make(Jwt::class);
        $this->auth = ['Authorization' => 'Bearer '.LoginClaims::default($this->phone, $this->user, AuthMethod::Password, 'mobile', $jwt)->token($jwt)];
    }

    #[Parity('config:PUSH_ENABLED')]
    #[Parity('config:PUSH_RELAY_URI')]
    #[Parity('config:PUSH_IDENTITY_URI')]
    #[Parity('config:PUSH_INSTALLATION_ID')]
    #[Parity('config:PUSH_INSTALLATION_KEY')]
    public function test_a_phone_registers_and_hears_of_changes(): void
    {
        $this->putJson("/api/devices/identifier/{$this->phone->uuid}/token", ['pushToken' => 'fcm-token'], $this->auth)->assertStatus(200);
        $folder = $this->postJson('/api/folders', ['name' => '2.folder'], $this->auth)->assertStatus(200)->json('id');
        $cipher = $this->postJson('/api/ciphers', ['type' => 1, 'name' => '2.login', 'login' => (object) [], 'encryptedFor' => $this->user->uuid], $this->auth)
            ->assertStatus(200)->json('id');
        $this->putJson("/api/devices/identifier/{$this->phone->uuid}/clear-token", [])->assertStatus(200);

        $recorded = $this->recorded();
        $this->assertSame(['/identity/connect/token', '/push/register', '/push/send', '/push/send', '/push/delete'], array_column($recorded, 'path'));

        // One token, kept for half of its lifetime.
        $this->assertEquals(['grant_type' => 'client_credentials', 'scope' => 'api.push', 'client_id' => 'installation.'.self::INSTALLATION,
            'client_secret' => self::installationKey()], $recorded[0]['body']);
        $this->assertSame(['application/x-www-form-urlencoded', '*/*'], [$recorded[0]['contentType'], $recorded[0]['accept']]);
        foreach (array_slice($recorded, 1) as $request) {
            $this->assertSame('Bearer relay-token-'.self::INSTALLATION, $request['authorization']);
        }

        // Keys sorted like json!() does.
        $this->assertSame(['deviceId' => $this->phone->push_uuid, 'identifier' => $this->phone->uuid, 'installationId' => self::INSTALLATION,
            'pushToken' => 'fcm-token', 'type' => 0, 'userId' => $this->user->uuid], $recorded[1]['body']);
        $this->assertSame(['application/json', 'application/json'], [$recorded[1]['contentType'], $recorded[1]['accept']]);

        $folderPush = $this->arrayOf($recorded[2]['body']);
        $this->assertSame(['clientType', 'deviceId', 'identifier', 'installationId', 'organizationId', 'payload', 'type', 'userId'], array_keys($folderPush));
        $this->assertSame([7, $this->phone->push_uuid, $this->phone->uuid, $this->user->uuid], [$folderPush['type'], $folderPush['deviceId'], $folderPush['identifier'], $folderPush['userId']]);
        $this->assertSame(['id', 'revisionDate', 'userId'], array_keys($this->arrayOf($folderPush['payload'])));
        $this->assertSame($folder, $this->arrayOf($folderPush['payload'])['id']);

        $cipherPush = $this->arrayOf($recorded[3]['body']);
        $this->assertSame(1, $cipherPush['type']);
        $this->assertSame(['collectionIds' => null, 'id' => $cipher, 'organizationId' => null], array_intersect_key($this->arrayOf($cipherPush['payload']),
            ['collectionIds' => 0, 'id' => 0, 'organizationId' => 0]));

        // Vaultwarden 80d18594: the push id in a JSON body, not in the path.
        $this->assertSame(['id' => $this->phone->push_uuid], $recorded[4]['body']);
        $this->assertSame(['application/json', 'application/json'], [$recorded[4]['contentType'], $recorded[4]['accept']]);

        $this->assertNull(Device::findByUuid($this->phone->uuid)?->push_token);
    }

    public function test_a_logout_reaches_the_phone(): void
    {
        $this->putJson("/api/devices/identifier/{$this->phone->uuid}/token", ['pushToken' => 'fcm-token'], $this->auth)->assertStatus(200);
        Device::new(Random::uuid(), $this->user->uuid, 'cli', 25)->save();
        $this->postJson('/api/accounts/security-stamp', ['masterPasswordHash' => 'client-hash'], $this->auth)->assertStatus(200);

        $logout = $this->arrayOf(array_column($this->recorded(), 'body')[2] ?? null);
        $this->assertSame(['clientType' => null, 'deviceId' => null, 'identifier' => null, 'installationId' => null, 'organizationId' => null,
            'payload' => ['date' => $this->arrayOf($logout['payload'])['date'] ?? null, 'userId' => $this->user->uuid], 'type' => 11, 'userId' => $this->user->uuid], $logout);
    }

    /**
     * Vaultwarden e056359a: the logout reaches the phone after the user and
     * its devices are gone.
     */
    public function test_a_deleted_user_is_signed_out_of_the_phone(): void
    {
        $this->putJson("/api/devices/identifier/{$this->phone->uuid}/token", ['pushToken' => 'fcm-token'], $this->auth)->assertStatus(200);
        $this->json('DELETE', '/api/accounts', ['masterPasswordHash' => 'client-hash'], $this->auth)->assertStatus(200);

        $recorded = $this->recorded();
        $this->assertSame(['/identity/connect/token', '/push/register', '/push/send'], array_column($recorded, 'path'));
        $logout = $this->arrayOf($recorded[2]['body']);
        $this->assertSame([11, $this->user->uuid, null], [$logout['type'], $logout['userId'], $logout['deviceId']]);
    }

    public function test_users_without_a_phone_send_nothing(): void
    {
        $this->postJson('/api/folders', ['name' => '2.folder'], $this->auth)->assertStatus(200);
        // Without a push token the phone is not registered either.
        $this->putJson("/api/devices/identifier/{$this->phone->uuid}/clear-token", [])->assertStatus(200);

        $this->assertSame(['/identity/connect/token', '/push/delete'], array_column($this->recorded(), 'path'));
    }

    public function test_a_relay_that_refuses_the_installation(): void
    {
        $this->changeVaultwardenEnvironment(['PUSH_INSTALLATION_KEY' => 'wrong']);

        $this->putJson("/api/devices/identifier/{$this->phone->uuid}/token", ['pushToken' => 'fcm-token'], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Unexpected push token received from bitwarden server: error decoding response body');
        // Notifications only log the failure.
        $this->postJson('/api/folders', ['name' => '2.folder'], $this->auth)->assertStatus(200);
    }

    public function test_a_relay_that_refuses_the_unregistration(): void
    {
        // The identity server stays, the relay answers 404 below another path.
        $relay = 'https://'.self::$servicesHost.$this->relay;
        $this->changeVaultwardenEnvironment(['PUSH_RELAY_URI' => "{$relay}/elsewhere", 'PUSH_IDENTITY_URI' => "{$relay}/identity"]);

        $this->putJson("/api/devices/identifier/{$this->phone->uuid}/clear-token", [])->assertStatus(400)->assertJsonPath('message',
            "An error occurred during device unregistration: HTTP status client error (404 Not Found) for url ({$relay}/elsewhere/push/delete)");
    }

    /**
     * What the relay of this test received, in order: method, path,
     * contentType, accept, authorization and the decoded body of each request.
     *
     * @return list<array<mixed>>
     */
    private function recorded(): array
    {
        $recorded = json_decode(self::fromServices("{$this->relay}/recorded"), true);

        return array_values(array_map($this->arrayOf(...), $this->arrayOf($recorded)));
    }

    private static function installationKey(): string
    {
        return substr(hash('sha256', 'relay:'.self::INSTALLATION), 0, 20);
    }

    /**
     * @return array<mixed>
     */
    private function arrayOf(mixed $value): array
    {
        $this->assertIsArray($value);

        return $value;
    }
}
