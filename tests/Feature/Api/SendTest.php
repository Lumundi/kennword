<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Device;
use App\Models\Membership;
use App\Models\OrgPolicy;
use App\Models\Send;
use App\Models\User;
use App\Support\Dates;
use App\Support\Random;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * src/api/core/sends.rs and the send_access grant of src/api/identity.rs.
 */
class SendTest extends TestCase
{
    use UsesVaultwardenDatabase;

    /**
     * @var array<string, string>
     */
    private array $auth;

    private User $user;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');

        $this->user = User::new('sends@example.com');
        $this->user->save();
        $device = Device::new(Random::uuid(), $this->user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->auth = ['Authorization' => 'Bearer '.LoginClaims::default($device, $this->user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];
    }

    public function test_text_send_lifecycle(): void
    {
        $created = $this->postJson('/api/sends', $this->text(['password' => 'pw', 'maxAccessCount' => '3', 'text' => ['text' => '2.t', 'hidden' => false, 'response' => 'x']]), $this->auth)
            ->assertStatus(200)
            ->assertJsonPath('object', 'send')
            ->assertJsonPath('type', 0)
            ->assertJsonPath('text', ['hidden' => false, 'text' => '2.t'])
            ->assertJsonPath('file', null)
            ->assertJsonPath('authType', 1)
            ->assertJsonPath('maxAccessCount', 3)
            ->assertJsonPath('hideEmail', false);
        $id = $this->string($created->json('id'));
        $this->assertSame(Send::findByUuid($id)?->accessId(), $created->json('accessId'));
        $this->assertSame('{"hidden":false,"text":"2.t"}', Send::findByUuid($id)->data ?? null);

        $this->get('/api/sends', $this->auth)->assertJsonPath('object', 'list')->assertJsonCount(1, 'data');
        $this->get("/api/sends/{$id}", $this->auth)->assertJsonPath('id', $id);
        $this->get('/api/sends/'.Random::uuid(), $this->auth)->assertStatus(400)->assertJsonPath('message', 'Send not found');

        // Without a password the old one stays.
        $this->putJson("/api/sends/{$id}", $this->text(['name' => '2.renamed', 'text' => ['text' => '2.u']]), $this->auth)
            ->assertJsonPath('name', '2.renamed')->assertJsonPath('text.text', '2.u')->assertJsonPath('authType', 1)->assertJsonPath('maxAccessCount', null);
        $this->putJson("/api/sends/{$id}", [...$this->text(), 'type' => 1, 'file' => ['fileName' => '2.f']], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', "Sends can't change type");
        $this->put("/api/sends/{$id}/remove-password", [], $this->auth)->assertJsonPath('authType', 2)->assertJsonPath('password', null);

        $this->delete("/api/sends/{$id}", [], $this->auth)->assertStatus(200)->assertContent('');
        $this->assertNull(Send::findByUuid($id));
    }

    public function test_invalid_sends(): void
    {
        $this->postJson('/api/sends', [...$this->text(), 'type' => 1, 'file' => []], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'File sends should use /api/sends/file/v2');
        $this->postJson('/api/sends', [...$this->text(), 'type' => 5], $this->auth)->assertStatus(400)->assertJsonPath('message', 'Invalid Send type');
        $this->postJson('/api/sends', [...$this->text(), 'text' => null], $this->auth)->assertStatus(400)->assertJsonPath('message', 'Send data not provided');
        $this->postJson('/api/sends', $this->text(['deletionDate' => Dates::format(Dates::now()->modify('+32 days'))]), $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.');
        $this->postJson('/api/sends', $this->text(['emails' => 'a@example.com']), $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Sends with email verification is not supported');
        $this->postJson('/api/sends', $this->text(['maxAccessCount' => 'x']), $this->auth)->assertStatus(400)->assertJsonPath('message', "Can't convert to number");
        $this->postJson('/api/sends', $this->text(['maxAccessCount' => 2_147_483_648]), $this->auth)->assertStatus(400)->assertJsonPath('message', 'Number does not fit in i32');
        $this->postJson('/api/sends', $this->text(['deletionDate' => 'tomorrow']), $this->auth)->assertStatus(422);
        $this->assertSame(0, Send::query()->count());
    }

    public function test_access_through_the_link(): void
    {
        $id = $this->string($this->postJson('/api/sends', $this->text(['maxAccessCount' => 1]), $this->auth)->json('id'));
        $accessId = (string) Send::findByUuid($id)?->accessId();

        $token = $this->string($this->accessToken($accessId)->assertStatus(200)
            ->assertJsonPath('token_type', 'Bearer')->assertJsonPath('scope', 'api.send.access')->json('access_token'));
        $this->post('/api/sends/access', [], ['Authorization' => "Bearer {$token}"])->assertStatus(200)
            ->assertJsonPath('object', 'send-access')
            ->assertJsonPath('id', $accessId)
            ->assertJsonPath('creatorIdentifier', 'sends@example.com')
            ->assertJsonPath('text.text', '2.t');
        $this->assertSame(1, $this->accessCount($id));

        // The limit is reached: no more access, and no more tokens.
        $this->post('/api/sends/access', [], ['Authorization' => "Bearer {$token}"])->assertStatus(404)
            ->assertJsonPath('message', 'Send does not exist or is no longer available');
        $this->accessToken($accessId)->assertStatus(404)->assertExactJson(['error' => 'invalid_grant', 'kind' => 'expected_server', 'send_access_error_type' => 'send_id_invalid']);

        $this->accessToken('not-an-access-id')->assertStatus(404)->assertJsonPath('send_access_error_type', 'send_id_invalid');
        $this->accessToken(null)->assertStatus(400)->assertJsonPath('message', 'send_id cannot be blank');
        $this->post('/api/sends/access')->assertStatus(401);
        $this->post('/api/sends/access', [], ['Authorization' => 'Bearer nope'])->assertStatus(401);
    }

    public function test_passwords_and_hidden_emails(): void
    {
        $id = $this->string($this->postJson('/api/sends', $this->text(['password' => 'secret-hash', 'hideEmail' => true]), $this->auth)->json('id'));
        $accessId = (string) Send::findByUuid($id)?->accessId();

        $this->accessToken($accessId)->assertStatus(400)
            ->assertExactJson(['error' => 'invalid_request', 'kind' => 'expected_server', 'send_access_error_type' => 'password_hash_b64_required']);
        $this->accessToken($accessId, 'wrong')->assertStatus(404)->assertJsonPath('send_access_error_type', 'password_hash_b64_invalid');
        $token = $this->string($this->accessToken($accessId, 'secret-hash')->assertStatus(200)->json('access_token'));

        $this->post('/api/sends/access', [], ['Authorization' => "Bearer {$token}"])->assertJsonPath('creatorIdentifier', null);
    }

    #[Parity('config:SENDS_FOLDER')]
    public function test_file_send(): void
    {
        $created = $this->postJson('/api/sends/file/v2', $this->file('2.file/name', 11), $this->auth)->assertStatus(200)
            ->assertJsonPath('object', 'send-fileUpload')
            ->assertJsonPath('fileUploadType', 0)
            ->assertJsonPath('sendResponse.file.fileName', '2.file/name')
            ->assertJsonPath('sendResponse.file.size', '11')
            ->assertJsonPath('sendResponse.file.sizeName', '11.00 bytes');
        $id = $this->string($created->json('sendResponse.id'));
        $fileId = $this->string($created->json('sendResponse.file.id'));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $fileId);
        $created->assertJsonPath('url', "/sends/{$id}/file/{$fileId}");

        $this->upload("/api/sends/{$id}/file/{$fileId}", UploadedFile::fake()->createWithContent('2.other', 'hello world'))
            ->assertStatus(400)->assertJsonPath('message', 'Send file name does not match.');
        $this->upload("/api/sends/{$id}/file/{$fileId}", UploadedFile::fake()->createWithContent('2.file/name', 'hello'))
            ->assertStatus(400)->assertJsonPath('message', 'Send file size does not match.');
        $this->upload("/api/sends/{$id}/file/0123", UploadedFile::fake()->createWithContent('2.file/name', 'hello world'))
            ->assertStatus(400)->assertJsonPath('message', 'Send file does not match send data.');
        $this->upload("/api/sends/{$id}/file/{$fileId}", UploadedFile::fake()->createWithContent('2.file/name', 'hello world'))->assertStatus(200)->assertContent('');
        $this->upload("/api/sends/{$id}/file/{$fileId}", UploadedFile::fake()->createWithContent('2.file/name', 'hello world'))
            ->assertStatus(400)->assertJsonPath('message', 'Io');
        // The CLI may send just the end of the name.
        $this->upload("/api/sends/{$id}/file/{$fileId}", UploadedFile::fake()->createWithContent('name', 'hello world'))
            ->assertStatus(400)->assertJsonPath('message', 'Io');

        $token = $this->string($this->accessToken((string) Send::findByUuid($id)?->accessId())->json('access_token'));
        $this->post('/api/sends/access', [], ['Authorization' => "Bearer {$token}"])->assertJsonPath('file.id', $fileId);
        $this->assertSame(0, $this->accessCount($id));
        $this->post('/api/sends/access/file/nope', [], ['Authorization' => "Bearer {$token}"])->assertStatus(404);
        $url = $this->string($this->post("/api/sends/access/file/{$fileId}", [], ['Authorization' => "Bearer {$token}"])
            ->assertStatus(200)->assertJsonPath('object', 'send-fileDownload')->assertJsonPath('id', $fileId)->json('url'));
        $this->assertSame(1, $this->accessCount($id));

        $download = $this->get(parse_url($url, PHP_URL_PATH).'?'.parse_url($url, PHP_URL_QUERY))->assertStatus(200)->assertHeaderMissing('Content-Type');
        $this->assertSame('hello world', $download->streamedContent());
        $this->get("/api/sends/{$id}/{$fileId}?t=nope")->assertStatus(404)->assertJsonPath('error.code', 404);
        $this->get("/api/sends/{$id}/{$fileId}")->assertStatus(404);

        // Unlike Vaultwarden, the download token ends with its Send's validity.
        $send = Send::findByUuid($id);
        $this->assertNotNull($send);
        $send->disabled = true;
        $send->save();
        $this->get(parse_url($url, PHP_URL_PATH).'?'.parse_url($url, PHP_URL_QUERY))->assertStatus(404);
        $send->disabled = false;
        $send->save();
        $this->get(parse_url($url, PHP_URL_PATH).'?'.parse_url($url, PHP_URL_QUERY))->assertStatus(200);

        $this->assertFileExists(Send::filePath($id, $fileId));
        $this->delete("/api/sends/{$id}", [], $this->auth)->assertStatus(200);
        $this->assertDirectoryDoesNotExist(dirname(Send::filePath($id, $fileId)));
    }

    public function test_invalid_file_sends(): void
    {
        $this->postJson('/api/sends/file/v2', $this->text(), $this->auth)->assertStatus(400)->assertJsonPath('message', 'Send content is not a file');
        $this->postJson('/api/sends/file/v2', [...$this->file('2.f', 1), 'fileLength' => null], $this->auth)->assertStatus(400)->assertJsonPath('message', 'Invalid send length');
        $this->postJson('/api/sends/file/v2', $this->file('2.f', -1), $this->auth)->assertStatus(400)->assertJsonPath('message', "Send size can't be negative");
        $this->postJson('/api/sends/file/v2', $this->file('2.f', 550_502_401), $this->auth)->assertStatus(400)->assertJsonPath('message', 'Send storage limit exceeded with this file');
        $this->postJson('/api/sends/file/v2', [...$this->file('2.f', 1), 'fileLength' => 1.5], $this->auth)->assertStatus(422);
    }

    #[Parity('config:USER_SEND_LIMIT')]
    public function test_send_storage_limit(): void
    {
        $this->changeVaultwardenEnvironment(['USER_SEND_LIMIT' => '1']);
        $this->postJson('/api/sends/file/v2', $this->file('2.f', 1025), $this->auth)->assertStatus(400)->assertJsonPath('message', 'Send storage limit exceeded with this file');
        $this->postJson('/api/sends/file/v2', $this->file('2.f', 1024), $this->auth)->assertStatus(200);
        $this->postJson('/api/sends/file/v2', $this->file('2.f', 1), $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Send storage limit reached! Delete some sends to free up space');
    }

    /**
     * Vaultwarden acb574b7: only `size` counts, not `Size`; and like any
     * derived struct, the data may hold it in a sequence.
     */
    public function test_the_storage_limit_counts_the_size_field(): void
    {
        foreach (['{"Size":1024}', '{"size":"1000","Size":24}', '[24]', '[24, 1]', '{"size":1.5}', '{"size":"x"}'] as $data) {
            $send = Send::new(Send::TYPE_FILE, '2.old', $data, '2.k', Dates::now()->modify('+1 day'));
            $send->user_uuid = $this->user->uuid;
            $send->save();
        }

        $this->assertSame(1024, Send::sizeByUser($this->user->uuid));
        $this->changeVaultwardenEnvironment(['USER_SEND_LIMIT' => '1']);
        $this->postJson('/api/sends/file/v2', $this->file('2.f', 1), $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Send storage limit reached! Delete some sends to free up space');
    }

    public function test_file_data_must_be_an_object(): void
    {
        $this->postJson('/api/sends/file/v2', [...$this->file('2.f', 1), 'file' => ['2.f']], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Invalid Send file data');
        $this->assertSame(0, Send::query()->count());
    }

    public function test_file_uploads_can_be_disabled(): void
    {
        $this->changeVaultwardenEnvironment(['USER_SEND_LIMIT' => '0']);
        $this->postJson('/api/sends/file/v2', $this->file('2.f', 1), $this->auth)->assertStatus(400)->assertJsonPath('message', 'File uploads are disabled');
    }

    #[Parity('config:SENDS_ALLOWED')]
    public function test_sends_can_be_disallowed(): void
    {
        $send = Send::new(Send::TYPE_TEXT, '2.old', '{}', '2.k', Dates::now()->modify('+1 day'));
        $send->user_uuid = $this->user->uuid;
        $send->save();

        $this->changeVaultwardenEnvironment(['SENDS_ALLOWED' => 'false']);
        $message = 'Due to an Enterprise Policy, you are only able to delete an existing Send.';
        $this->postJson('/api/sends', $this->text(), $this->auth)->assertStatus(400)->assertJsonPath('message', $message);
        $this->putJson("/api/sends/{$send->uuid}", $this->text(), $this->auth)->assertStatus(400)->assertJsonPath('message', $message);
        $this->delete("/api/sends/{$send->uuid}", [], $this->auth)->assertStatus(200);
    }

    public function test_organization_policies(): void
    {
        $org = Random::uuid();
        DB::table('users_organizations')->insert(['uuid' => Random::uuid(), 'user_uuid' => $this->user->uuid, 'org_uuid' => $org,
            'access_all' => false, 'akey' => '2.k', 'status' => Membership::STATUS_CONFIRMED, 'atype' => Membership::TYPE_USER]);
        DB::table('org_policies')->insert(['uuid' => Random::uuid(), 'org_uuid' => $org, 'atype' => OrgPolicy::TYPE_SEND_OPTIONS,
            'enabled' => true, 'data' => '{"disableHideEmail":true}']);

        $this->postJson('/api/sends', $this->text(['hideEmail' => true]), $this->auth)->assertStatus(400)
            ->assertJsonPath('message', 'Due to an Enterprise Policy, you are not allowed to hide your email address from recipients when creating or editing a Send.');
        $this->postJson('/api/sends', $this->text(['hideEmail' => false]), $this->auth)->assertStatus(200);

        DB::table('org_policies')->insert(['uuid' => Random::uuid(), 'org_uuid' => $org, 'atype' => OrgPolicy::TYPE_DISABLE_SEND, 'enabled' => true, 'data' => '{}']);
        $this->postJson('/api/sends', $this->text(), $this->auth)->assertStatus(400)
            ->assertJsonPath('message', 'Due to an Enterprise Policy, you are only able to delete an existing Send.');

        // Admins are exempt.
        DB::table('users_organizations')->where('org_uuid', $org)->update(['atype' => Membership::TYPE_ADMIN]);
        $this->postJson('/api/sends', $this->text(['hideEmail' => true]), $this->auth)->assertStatus(200);
    }

    /**
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    private function text(array $changes = []): array
    {
        return [
            'type' => 0,
            'key' => '2.key',
            'name' => '2.name',
            'text' => ['text' => '2.t', 'hidden' => false],
            'deletionDate' => Dates::format(Dates::now()->modify('+7 days')),
            'disabled' => false,
            ...$changes,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function file(string $fileName, int $length): array
    {
        return [...$this->text(), 'type' => 1, 'text' => null, 'file' => ['fileName' => $fileName], 'fileLength' => $length];
    }

    /**
     * @return TestResponse<Response>
     */
    private function accessToken(?string $accessId, ?string $password = null): TestResponse
    {
        $fields = array_filter(['grant_type' => 'send_access', 'client_id' => 'send', 'send_id' => $accessId, 'password_hash_b64' => $password], static fn (?string $value): bool => $value !== null);

        return $this->call('POST', '/identity/connect/token', server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], content: http_build_query($fields));
    }

    /**
     * @return TestResponse<Response>
     */
    private function upload(string $uri, UploadedFile $file): TestResponse
    {
        return $this->call('POST', $uri, [], [], ['data' => $file], $this->transformHeadersToServerVars([...$this->auth, 'Content-Type' => 'multipart/form-data; boundary=x']));
    }

    private function accessCount(string $sendId): ?int
    {
        return Send::findByUuid($sendId)?->access_count;
    }

    private function string(mixed $value): string
    {
        $this->assertIsString($value);

        return $value;
    }
}
