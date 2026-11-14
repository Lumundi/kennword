<?php

namespace Tests\Feature\Api;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Http\Data\UploadData;
use App\Models\Attachment;
use App\Models\Cipher;
use App\Models\CollectionCipher;
use App\Models\Device;
use App\Models\User;
use App\Support\Random;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\File\UploadedFile as SymfonyUploadedFile;
use Symfony\Component\HttpFoundation\Response;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * The attachment routes of src/api/core/ciphers.rs and the download of src/api/web.rs.
 */
class AttachmentTest extends TestCase
{
    use UsesVaultwardenDatabase;

    /**
     * @var array<string, string>
     */
    private array $auth;

    private User $user;

    private string $cipherId;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');

        $this->user = User::new('attachments@example.com');
        $this->user->save();
        $device = Device::new(Random::uuid(), $this->user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $this->auth = ['Authorization' => 'Bearer '.LoginClaims::default($device, $this->user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];

        $id = $this->postJson('/api/ciphers', ['type' => 2, 'name' => '2.note', 'encryptedFor' => $this->user->uuid, 'secureNote' => ['type' => 0]], $this->auth)->json('id');
        $this->assertIsString($id);
        $this->cipherId = $id;
    }

    #[Parity('config:ATTACHMENTS_FOLDER')]
    public function test_v2_upload_and_download(): void
    {
        $created = $this->postJson("/api/ciphers/{$this->cipherId}/attachment/v2", ['key' => '2.key', 'fileName' => '2.name', 'fileSize' => '5'], $this->auth)
            ->assertStatus(200)
            ->assertJsonPath('object', 'attachment-fileUpload')
            ->assertJsonPath('fileUploadType', 0)
            ->assertJsonPath('cipherResponse.id', $this->cipherId);
        $attachmentId = $created->json('attachmentId');
        $this->assertIsString($attachmentId);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{20}$/', $attachmentId);
        $created->assertJsonPath('url', "/ciphers/{$this->cipherId}/attachment/{$attachmentId}");

        $this->upload("/api/ciphers/{$this->cipherId}/attachment/{$attachmentId}", UploadedFile::fake()->createWithContent('ignored', 'hello world'))
            ->assertStatus(200)->assertContent('');
        $this->assertSame(11, Attachment::findById($attachmentId)?->file_size);

        // Ids are looked up in lower case.
        $this->get("/api/ciphers/{$this->cipherId}/attachment/".strtoupper($attachmentId), $this->auth)->assertStatus(200)->assertJsonPath('id', $attachmentId);
        $this->get('/api/ciphers/'.Random::uuid()."/attachment/{$attachmentId}", $this->auth)->assertStatus(400)->assertJsonPath('message', "Cipher doesn't exist");
        $url = $this->get("/api/ciphers/{$this->cipherId}/attachment/{$attachmentId}", $this->auth)->assertStatus(200)
            ->assertJsonPath('size', '11')->assertJsonPath('sizeName', '11.00 bytes')->assertJsonPath('key', '2.key')->json('url');
        $this->assertIsString($url);
        $this->assertStringContainsString("/attachments/{$this->cipherId}/{$attachmentId}?token=", $url);

        $download = $this->get(parse_url($url, PHP_URL_PATH).'?'.parse_url($url, PHP_URL_QUERY))->assertStatus(200)->assertHeaderMissing('Content-Type');
        $this->assertSame('hello world', $download->streamedContent());
        $this->get("/attachments/{$this->cipherId}/{$attachmentId}?token=nope")->assertStatus(404);
        $this->get("/attachments/{$this->cipherId}/{$attachmentId}")->assertStatus(404);
        $query = (string) parse_url($url, PHP_URL_QUERY);
        $this->get("/attachments/{$this->cipherId}/{$attachmentId}?{$query}&token=nope")->assertStatus(200);
        $this->get("/attachments/{$this->cipherId}/{$attachmentId}?token=nope&{$query}")->assertStatus(404);

        $this->get('/api/ciphers/'.$this->cipherId, $this->auth)->assertJsonPath('attachments.0.id', $attachmentId);
    }

    public function test_v2_size_must_match(): void
    {
        $attachmentId = $this->postJson("/api/ciphers/{$this->cipherId}/attachment/v2", ['key' => '2.key', 'fileName' => '2.name', 'fileSize' => 3 * 1024 * 1024], $this->auth)->json('attachmentId');
        $this->assertIsString($attachmentId);

        $this->upload("/api/ciphers/{$this->cipherId}/attachment/{$attachmentId}", UploadedFile::fake()->createWithContent('x', 'tiny'))
            ->assertStatus(400)->assertJsonPath('message', 'Attachment size mismatch (expected within [2097152, 4194304], got 4)');
        $this->assertNull(Attachment::findById($attachmentId));

        $this->postJson("/api/ciphers/{$this->cipherId}/attachment/v2", ['key' => '2.k', 'fileName' => '2.n', 'fileSize' => -1], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', "Attachment size can't be negative");
        $this->postJson("/api/ciphers/{$this->cipherId}/attachment/v2", ['key' => '2.k', 'fileName' => '2.n', 'fileSize' => 550_502_401], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Max file size is 525 MB.');
        $this->postJson("/api/ciphers/{$this->cipherId}/attachment/v2", ['key' => '2.k', 'fileName' => '2.n', 'fileSize' => '1.5'], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', "Can't convert to number");
        $this->postJson("/api/ciphers/{$this->cipherId}/attachment/v2", ['key' => '2.k', 'fileName' => '2.n', 'fileSize' => 1.5], $this->auth)->assertStatus(422);
    }

    public function test_legacy_upload_share_and_delete(): void
    {
        // Encrypted names hold slashes; PHP would cut them at the last one.
        $cipher = $this->upload("/api/ciphers/{$this->cipherId}/attachment", UploadedFile::fake()->createWithContent('2.iv/x|ct+y/z==', 'secret'), ['key' => '2.key'])
            ->assertStatus(200)->assertJsonPath('attachments.0.fileName', '2.iv/x|ct+y/z==')->assertJsonPath('attachments.0.size', '6');
        $first = $cipher->json('attachments.0.id');
        $this->assertIsString($first);
        $this->assertFileExists(Attachment::path($this->cipherId, $first));

        $this->upload("/api/ciphers/{$this->cipherId}/attachment", UploadedFile::fake()->createWithContent('2.n', 'x'))
            ->assertStatus(400)->assertJsonPath('message', 'No attachment key provided');
        $this->call('POST', "/api/ciphers/{$this->cipherId}/attachment", ['key' => '2.k', 'data' => 'plain'], [], [], $this->transformHeadersToServerVars([...$this->auth, 'Content-Type' => 'multipart/form-data; boundary=x']))
            ->assertStatus(400)->assertJsonPath('message', 'No filename provided');
        $this->postJson("/api/ciphers/{$this->cipherId}/attachment", ['key' => '2.k'], $this->auth)->assertStatus(404)->assertJsonPath('error.code', 404);
        $this->post("/api/ciphers/{$this->cipherId}/attachment", [], ['Content-Type' => 'application/json'])->assertStatus(404);

        $shared = $this->upload("/api/ciphers/{$this->cipherId}/attachment/{$first}/share", UploadedFile::fake()->createWithContent('2.other', 'new data'), ['key' => '2.key2'])
            ->assertStatus(200)->assertJsonCount(1, 'attachments')->assertJsonPath('attachments.0.fileName', '2.other');
        $second = $shared->json('attachments.0.id');
        $this->assertIsString($second);
        $this->assertFileDoesNotExist(Attachment::path($this->cipherId, $first));

        $this->delete("/api/ciphers/{$this->cipherId}/attachment/{$first}", [], $this->auth)->assertStatus(400)->assertJsonPath('message', "Attachment doesn't exist");
        $this->delete('/api/ciphers/'.Random::uuid()."/attachment/{$second}", [], $this->auth)->assertStatus(400)->assertJsonPath('message', 'Attachment from other cipher');
        $this->post("/api/ciphers/{$this->cipherId}/attachment/{$second}/delete", [], $this->auth)
            ->assertStatus(200)->assertJsonPath('cipher.id', $this->cipherId)->assertJsonPath('cipher.attachments', null);
        $this->assertFileDoesNotExist(Attachment::path($this->cipherId, $second));
        $this->delete("/api/ciphers/{$this->cipherId}/attachment/no_such!id", [], $this->auth)->assertStatus(422);
    }

    #[Parity('config:USER_ATTACHMENT_LIMIT')]
    public function test_attachments_can_be_disabled(): void
    {
        $this->changeVaultwardenEnvironment(['USER_ATTACHMENT_LIMIT' => '0']);
        $this->upload("/api/ciphers/{$this->cipherId}/attachment", UploadedFile::fake()->createWithContent('2.n', 'x'), ['key' => '2.k'])
            ->assertStatus(400)->assertJsonPath('message', 'Attachments are disabled');
    }

    #[Parity('config:USER_ATTACHMENT_LIMIT')]
    public function test_storage_limit(): void
    {
        $this->changeVaultwardenEnvironment(['USER_ATTACHMENT_LIMIT' => '1']);
        $this->upload("/api/ciphers/{$this->cipherId}/attachment", UploadedFile::fake()->createWithContent('2.n', str_repeat('x', 1025)), ['key' => '2.k'])
            ->assertStatus(400)->assertJsonPath('message', 'Attachment storage limit exceeded with this file');
        $this->upload("/api/ciphers/{$this->cipherId}/attachment", UploadedFile::fake()->createWithContent('2.n', str_repeat('x', 1024)), ['key' => '2.k'])
            ->assertStatus(200);
        $this->upload("/api/ciphers/{$this->cipherId}/attachment", UploadedFile::fake()->createWithContent('2.n', 'x'), ['key' => '2.k'])
            ->assertStatus(400)->assertJsonPath('message', 'Attachment storage limit reached! Delete some attachments to free up space');
    }

    #[Parity('config:USER_ATTACHMENT_LIMIT')]
    public function test_v2_reservation_counts_against_the_limit(): void
    {
        // Vaultwarden a96912bf: the announced size is checked before the record is saved.
        $this->changeVaultwardenEnvironment(['USER_ATTACHMENT_LIMIT' => '1']);
        $this->postJson("/api/ciphers/{$this->cipherId}/attachment/v2", ['key' => '2.k', 'fileName' => '2.n', 'fileSize' => 1025], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Attachment storage limit exceeded with this file');
        $this->assertSame(0, Attachment::query()->count());

        $attachmentId = $this->postJson("/api/ciphers/{$this->cipherId}/attachment/v2", ['key' => '2.k', 'fileName' => '2.n', 'fileSize' => 1024], $this->auth)
            ->assertStatus(200)->json('attachmentId');
        $this->assertIsString($attachmentId);
        $this->postJson("/api/ciphers/{$this->cipherId}/attachment/v2", ['key' => '2.k', 'fileName' => '2.n', 'fileSize' => 1], $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Attachment storage limit reached! Delete some attachments to free up space');

        // The upload of the reserved record is credited with its own size.
        $this->upload("/api/ciphers/{$this->cipherId}/attachment/{$attachmentId}", UploadedFile::fake()->createWithContent('x', str_repeat('x', 1024)))
            ->assertStatus(200);
    }

    #[Parity('config:ORG_ATTACHMENT_LIMIT')]
    public function test_organization_storage_limit(): void
    {
        // The user's limit does not apply to the ciphers of organizations.
        $this->changeVaultwardenEnvironment(['ORG_ATTACHMENT_LIMIT' => '1', 'USER_ATTACHMENT_LIMIT' => '0']);
        $org = $this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $this->auth)->json('id');
        $this->assertIsString($org);
        $collection = $this->get("/api/organizations/{$org}/collections", $this->auth)->json('data.0.id');
        $cipher = $this->postJson('/api/ciphers/create', ['cipher' => ['type' => 2, 'name' => '2.shared', 'encryptedFor' => $this->user->uuid,
            'secureNote' => ['type' => 0], 'organizationId' => $org], 'collectionIds' => [$collection]], $this->auth)->json('id');
        $this->assertIsString($cipher);

        $this->upload("/api/ciphers/{$cipher}/attachment", UploadedFile::fake()->createWithContent('2.n', str_repeat('x', 1025)), ['key' => '2.k'])
            ->assertStatus(400)->assertJsonPath('message', 'Attachment storage limit exceeded with this file');
        $this->upload("/api/ciphers/{$cipher}/attachment", UploadedFile::fake()->createWithContent('2.n', str_repeat('x', 1024)), ['key' => '2.k'])
            ->assertStatus(200);
        $this->upload("/api/ciphers/{$cipher}/attachment", UploadedFile::fake()->createWithContent('2.n', 'x'), ['key' => '2.k'])
            ->assertStatus(400)->assertJsonPath('message', 'Attachment storage limit reached! Delete some attachments to free up space');
        $this->upload("/api/ciphers/{$this->cipherId}/attachment", UploadedFile::fake()->createWithContent('2.n', 'x'), ['key' => '2.k'])
            ->assertStatus(400)->assertJsonPath('message', 'Attachments are disabled');
    }

    public function test_sharing_into_an_organization_brings_attachments_under_its_limit(): void
    {
        // Unlike Vaultwarden: the attachments of a personal cipher used to enter an organization past its limit.
        $this->changeVaultwardenEnvironment(['ORG_ATTACHMENT_LIMIT' => '1']);
        $org = $this->postJson('/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.owner-key', 'name' => '2.org', 'planType' => 0], $this->auth)->json('id');
        $this->assertIsString($org);
        $collection = $this->get("/api/organizations/{$org}/collections", $this->auth)->json('data.0.id');
        $this->upload("/api/ciphers/{$this->cipherId}/attachment", UploadedFile::fake()->createWithContent('2.n', str_repeat('x', 1025)), ['key' => '2.k'])
            ->assertStatus(200);
        $share = ['cipher' => ['type' => 2, 'name' => '2.note', 'encryptedFor' => $this->user->uuid, 'secureNote' => ['type' => 0], 'organizationId' => $org],
            'collectionIds' => [$collection]];

        $this->putJson("/api/ciphers/{$this->cipherId}/share", $share, $this->auth)
            ->assertStatus(400)->assertJsonPath('message', 'Attachment storage limit reached! Delete some attachments to free up space');
        $this->assertNull(Cipher::findByUuid($this->cipherId)?->organization_uuid);
        $this->assertSame([], CollectionCipher::collectionsOfCipher($this->cipherId));

        // What fits moves.
        $this->changeVaultwardenEnvironment(['ORG_ATTACHMENT_LIMIT' => '2']);
        $this->putJson("/api/ciphers/{$this->cipherId}/share", $share, $this->auth)->assertStatus(200)->assertJsonPath('organizationId', $org);
    }

    public function test_uploads_as_php_parses_them(): void
    {
        // Real requests carry Symfony's UploadedFile, with the whole name as its path.
        $path = tempnam(sys_get_temp_dir(), 'upload');
        $this->assertIsString($path);
        file_put_contents($path, 'bytes');
        $request = Request::create('/upload', 'POST', ['key' => '2.k'], [], ['data' => new SymfonyUploadedFile($path, '2.iv/x|y==', null, null, true)]);

        $data = UploadData::fromRequest($request);
        $this->assertSame('2.k', $data->key);
        $this->assertSame('2.iv/x|y==', $data->rawName());
        $this->assertSame(5, $data->size());
    }

    /**
     * @param  array<string, string>  $fields
     * @return TestResponse<Response>
     */
    private function upload(string $uri, UploadedFile $file, array $fields = []): TestResponse
    {
        return $this->call('POST', $uri, $fields, [], ['data' => $file], $this->transformHeadersToServerVars([...$this->auth, 'Content-Type' => 'multipart/form-data; boundary=x']));
    }
}
