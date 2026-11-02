<?php

namespace Tests\Feature\Notifications;

use App\Auth\AdminToken;
use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\LoginClaims;
use App\Models\Device;
use App\Models\User;
use App\Notifications\Channel;
use App\Support\Dates;
use App\Support\Random;
use App\Support\UpdateType;
use Illuminate\Http\UploadedFile;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\Fakes\NotificationsChannelFake;
use Tests\TestCase;

/**
 * The updates requests hand to the notifications daemon (api::Notify), at
 * the places Vaultwarden sends them.
 */
class NotifyTest extends TestCase
{
    use UsesVaultwardenDatabase;

    private const string NEW_DEVICE = '0d8f2c1e-3b4a-4c5d-9e6f-7a8b9c0d1e2f';

    private NotificationsChannelFake $channel;

    private User $user;

    private Device $device;

    /**
     * @var array<string, string>
     */
    private array $auth;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000', 'ADMIN_TOKEN' => 'admin-secret'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');
        $this->channel = new NotificationsChannelFake;
        $this->app->instance(Channel::class, $this->channel);

        $this->user = User::new('notify@example.com');
        $this->user->setPassword('client-hash', 'user-key', resetSecurityStamp: false, allowNextRoute: null);
        $this->user->save();
        $this->device = Device::new(Random::uuid(), $this->user->uuid, 'cli', 25);
        $this->device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->auth = ['Authorization' => 'Bearer '.LoginClaims::default($this->device, $this->user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];
    }

    public function test_folder_changes(): void
    {
        $id = $this->stringOf($this->postJson('/api/folders', ['name' => '2.folder'], $this->auth)->assertStatus(200)->json('id'));
        $this->putJson("/api/folders/{$id}", ['name' => '2.renamed'], $this->auth)->assertStatus(200);
        $this->delete("/api/folders/{$id}", [], $this->auth)->assertStatus(200);

        $updates = $this->channel->updates();
        $this->assertSame([UpdateType::SyncFolderCreate->value, UpdateType::SyncFolderUpdate->value, UpdateType::SyncFolderDelete->value],
            array_map(static fn (array $update): mixed => is_array($update['update']) ? $update['update']['Type'] : null, $updates));
        $this->assertSame([$this->user->uuid], $updates[0]['to']);
        $this->assertSame('ReceiveMessage', $updates[0]['target']);
        $update = $this->arrayOf($updates[2]['update']);
        $this->assertSame(['ContextId', 'Type', 'Payload'], array_keys($update));
        $this->assertSame($this->device->uuid, $update['ContextId']);
        $payload = $this->arrayOf($update['Payload']);
        $this->assertSame(['Id', 'UserId', 'RevisionDate'], array_keys($payload));
        $this->assertSame([$id, $this->user->uuid], [$payload['Id'], $payload['UserId']]);
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$/', $this->stringOf($payload['RevisionDate']));
    }

    public function test_cipher_changes(): void
    {
        $cipher = ['type' => 1, 'name' => '2.login', 'login' => (object) [], 'encryptedFor' => $this->user->uuid];
        $id = $this->stringOf($this->postJson('/api/ciphers', $cipher, $this->auth)->assertStatus(200)->json('id'));
        $this->putJson("/api/ciphers/{$id}", $cipher, $this->auth)->assertStatus(200);
        $this->putJson("/api/ciphers/{$id}/delete", [], $this->auth)->assertStatus(200);
        $this->putJson("/api/ciphers/{$id}/restore", [], $this->auth)->assertStatus(200);
        $this->postJson('/api/ciphers/move', ['ids' => [$id], 'folderId' => null], $this->auth)->assertStatus(200);
        $second = $this->stringOf($this->postJson('/api/ciphers', $cipher, $this->auth)->json('id'));
        $this->postJson('/api/ciphers/move', ['ids' => [$id, $second], 'folderId' => null], $this->auth)->assertStatus(200);
        $this->delete("/api/ciphers/{$id}", [], $this->auth)->assertStatus(200);
        $this->deleteJson('/api/ciphers', ['ids' => [$second]], $this->auth)->assertStatus(200);
        $this->postJson('/api/ciphers/import', ['ciphers' => [$cipher], 'folders' => [], 'folderRelationships' => []], $this->auth)->assertStatus(200);

        $this->assertSame([
            [UpdateType::SyncCipherCreate->value, $id],
            [UpdateType::SyncCipherUpdate->value, $id],
            [UpdateType::SyncCipherUpdate->value, $id],
            [UpdateType::SyncCipherUpdate->value, $id],
            [UpdateType::SyncCipherUpdate->value, $id],
            [UpdateType::SyncCipherCreate->value, $second],
            // Multi moves, deletes and imports ask for a full sync instead.
            [UpdateType::SyncCiphers->value, null],
            [UpdateType::SyncLoginDelete->value, $id],
            [UpdateType::SyncCiphers->value, null],
            [UpdateType::SyncVault->value, null],
        ], $this->typesAndIds());

        $user = $this->arrayOf($this->arrayOf($this->channel->updates()[6]['update'])['Payload']);
        $this->assertSame(['UserId', 'Date'], array_keys($user));
        $this->assertNull($this->arrayOf($this->channel->updates()[6]['update'])['ContextId']);
    }

    public function test_attachment_changes(): void
    {
        // Vaultwarden 64ae55ce: the v2 API notifies when it creates the record, not again after the upload.
        $cipher = ['type' => 1, 'name' => '2.login', 'login' => (object) [], 'encryptedFor' => $this->user->uuid];
        $id = $this->stringOf($this->postJson('/api/ciphers', $cipher, $this->auth)->assertStatus(200)->json('id'));
        $attachmentId = $this->stringOf($this->postJson("/api/ciphers/{$id}/attachment/v2", ['key' => '2.k', 'fileName' => '2.n', 'fileSize' => 5], $this->auth)
            ->assertStatus(200)->json('attachmentId'));
        $upload = fn (string $uri, array $fields = []) => $this->call('POST', $uri, $fields, [], ['data' => UploadedFile::fake()->createWithContent('2.n', 'hello')],
            $this->transformHeadersToServerVars([...$this->auth, 'Content-Type' => 'multipart/form-data; boundary=x']));
        $this->assertCount(2, $this->channel->updates());
        $upload("/api/ciphers/{$id}/attachment/{$attachmentId}")->assertStatus(200);
        $this->assertCount(2, $this->channel->updates());
        $upload("/api/ciphers/{$id}/attachment", ['key' => '2.k'])->assertStatus(200);

        $this->assertSame([
            [UpdateType::SyncCipherCreate->value, $id],
            [UpdateType::SyncCipherUpdate->value, $id],
            [UpdateType::SyncCipherUpdate->value, $id],
        ], $this->typesAndIds());
    }

    public function test_send_changes_and_anonymous_access(): void
    {
        $send = ['type' => 0, 'key' => '2.key', 'name' => '2.name', 'text' => ['text' => '2.t', 'hidden' => false],
            'deletionDate' => Dates::format(Dates::now()->modify('+7 days')), 'disabled' => false];
        $created = $this->postJson('/api/sends', $send, $this->auth)->assertStatus(200);
        $id = $this->stringOf($created->json('id'));
        $token = $this->call('POST', '/identity/connect/token', server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            content: http_build_query(['grant_type' => 'send_access', 'client_id' => 'send', 'send_id' => $created->json('accessId')]))->json('access_token');
        $this->post('/api/sends/access', [], ['Authorization' => "Bearer {$this->stringOf($token)}"])->assertStatus(200);
        $this->delete("/api/sends/{$id}", [], $this->auth)->assertStatus(200);

        $this->assertSame([
            [UpdateType::SyncSendCreate->value, $id],
            [UpdateType::SyncSendUpdate->value, $id],
            [UpdateType::SyncSendDelete->value, $id],
        ], $this->typesAndIds());
        // Sends carry no acting device.
        $this->assertNull($this->arrayOf($this->channel->updates()[0]['update'])['ContextId']);
    }

    public function test_settings_and_logouts(): void
    {
        $this->postJson('/api/settings/domains', ['equivalentDomains' => [], 'excludedGlobalEquivalentDomains' => []], $this->auth)->assertStatus(200);
        $this->postJson('/api/accounts/security-stamp', ['masterPasswordHash' => 'client-hash'], $this->auth)->assertStatus(200);

        $updates = $this->channel->updates();
        $this->assertSame([[UpdateType::SyncSettings->value, null], [UpdateType::LogOut->value, null]], $this->typesAndIds());
        // A new security stamp signs out every device, the asking one too.
        $this->assertNull($this->arrayOf($updates[1]['update'])['ContextId']);
    }

    public function test_login_with_a_device_reaches_both_hubs(): void
    {
        Device::new(self::NEW_DEVICE, $this->user->uuid, 'firefox', 10)->save();
        $id = $this->postJson('/api/auth-requests', ['accessCode' => 'code', 'deviceIdentifier' => self::NEW_DEVICE, 'email' => 'notify@example.com',
            'publicKey' => 'device-key'], ['HTTP_DEVICE_TYPE' => '10'])->assertStatus(200)->json('id');
        $id = $this->stringOf($id);
        $this->putJson("/api/auth-requests/{$id}", ['deviceIdentifier' => $this->device->uuid, 'key' => '4.key', 'requestApproved' => true], $this->auth)
            ->assertStatus(200);

        $updates = $this->channel->updates();
        $this->assertCount(3, $updates);
        $this->assertSame(['ContextId' => self::NEW_DEVICE, 'Type' => 15, 'Payload' => ['Id' => $id, 'UserId' => $this->user->uuid]], $updates[0]['update']);
        $this->assertSame($id, $updates[1]['to']);
        $this->assertSame('AuthRequestResponseRecieved', $updates[1]['target']);
        $this->assertSame(['Type' => 16, 'Payload' => ['Id' => $id, 'UserId' => $this->user->uuid], 'UserId' => $this->user->uuid], $updates[1]['update']);
        $this->assertSame(['ContextId' => $this->device->uuid, 'Type' => 16, 'Payload' => ['Id' => $id, 'UserId' => $this->user->uuid]], $updates[2]['update']);
    }

    #[Parity('route:POST /admin/users/{user_id}/deauth')]
    #[Parity('route:POST /admin/users/{user_id}/disable')]
    public function test_the_admin_signs_users_out(): void
    {
        $login = $this->call('POST', '/admin', server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], content: 'token=admin-secret');
        $cookie = null;
        foreach ($login->headers->getCookies() as $candidate) {
            $cookie = $candidate->getName() === AdminToken::COOKIE_NAME ? $candidate->getValue() : $cookie;
        }
        $this->assertIsString($cookie);

        // JSON requests carry cookies only with credentials.
        $this->withUnencryptedCookie(AdminToken::COOKIE_NAME, $cookie)->withCredentials();
        $this->postJson("/admin/users/{$this->user->uuid}/deauth", [])->assertStatus(200);
        $this->postJson("/admin/users/{$this->user->uuid}/disable", [])->assertStatus(200);

        $this->assertSame([[UpdateType::LogOut->value, null], [UpdateType::LogOut->value, null]], $this->typesAndIds());
        $this->assertSame([[$this->user->uuid], [$this->user->uuid]], array_column($this->channel->updates(), 'to'));
        $this->assertNull($this->arrayOf($this->channel->updates()[0]['update'])['ContextId']);
    }

    /**
     * Vaultwarden e056359a: a deleted user's clients are signed out.
     */
    public function test_deleted_users_are_signed_out(): void
    {
        $this->json('DELETE', '/api/accounts', ['masterPasswordHash' => 'client-hash'], $this->auth)->assertStatus(200);
        $this->assertSame([[UpdateType::LogOut->value, null]], $this->typesAndIds());
        $this->assertSame([[$this->user->uuid]], array_column($this->channel->updates(), 'to'));

        $second = User::new('second@example.com');
        $second->save();
        $jwt = $this->app->make(Jwt::class);
        $token = $jwt->encode(['nbf' => time(), 'exp' => time() + 60, 'iss' => $jwt->issuer(JwtIssuer::Delete), 'sub' => $second->uuid]);
        $this->postJson('/api/accounts/delete-recover-token', ['userId' => $second->uuid, 'token' => $token])->assertStatus(200);

        $third = User::new('third@example.com');
        $third->save();
        $login = $this->call('POST', '/admin', server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], content: 'token=admin-secret');
        $cookie = null;
        foreach ($login->headers->getCookies() as $candidate) {
            $cookie = $candidate->getName() === AdminToken::COOKIE_NAME ? $candidate->getValue() : $cookie;
        }
        $this->assertIsString($cookie);
        $this->withUnencryptedCookie(AdminToken::COOKIE_NAME, $cookie)->withCredentials();
        $this->postJson("/admin/users/{$third->uuid}/delete", [])->assertStatus(200);

        $this->assertSame([[$this->user->uuid], [$second->uuid], [$third->uuid]], array_column($this->channel->updates(), 'to'));
        $this->assertSame(array_fill(0, 3, [UpdateType::LogOut->value, null]), $this->typesAndIds());
    }

    public function test_nothing_is_sent_with_websockets_and_push_disabled(): void
    {
        $this->changeVaultwardenEnvironment(['ENABLE_WEBSOCKET' => 'false']);
        $this->app->instance(Channel::class, $this->channel);

        $this->postJson('/api/folders', ['name' => '2.folder'], $this->auth)->assertStatus(200);

        $this->assertSame([], $this->channel->sent);
    }

    public function test_the_hubs_only_exist_in_the_daemon(): void
    {
        $this->get('/notifications/hub', ['Connection' => 'Upgrade', 'Upgrade' => 'websocket', 'Sec-WebSocket-Version' => '13',
            'Sec-WebSocket-Key' => 'dGhlIHNhbXBsZSBub25jZQ=='])->assertStatus(404);
        $this->get('/notifications/anonymous-hub?token=x')->assertStatus(404);
    }

    /**
     * @return list<array{mixed, mixed}>
     */
    private function typesAndIds(): array
    {
        return array_map(function (array $update): array {
            $update = $this->arrayOf($update['update']);

            return [$update['Type'], $this->arrayOf($update['Payload'])['Id'] ?? null];
        }, $this->channel->updates());
    }

    /**
     * @return array<mixed>
     */
    private function arrayOf(mixed $value): array
    {
        $this->assertIsArray($value);

        return $value;
    }

    private function stringOf(mixed $value): string
    {
        $this->assertIsString($value);

        return $value;
    }
}
