<?php

namespace Tests\Differential;

use Tests\Attributes\Parity;

/**
 * src/api/core/sends.rs and the send_access grant on both servers.
 */
class SendTest extends DifferentialTestCase
{
    #[Parity('route:GET /api/sends')]
    #[Parity('route:GET /api/sends/{send_id}')]
    #[Parity('route:POST /api/sends')]
    #[Parity('route:PUT /api/sends/{send_id}')]
    #[Parity('route:PUT /api/sends/{send_id}/remove-password')]
    #[Parity('route:DELETE /api/sends/{send_id}')]
    public function test_text_sends(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, 'sends@example.com');
            $unknown = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
            $steps = [];

            $steps['create'] = $created = $server->json('POST', '/api/sends', self::text([
                'password' => 'pw', 'maxAccessCount' => '3', 'notes' => '2.notes', 'hideEmail' => true,
                'text' => ['text' => '2.t', 'hidden' => false, 'response' => 'x', 'Extra' => 1],
                'expirationDate' => '2030-01-01T02:00:00+02:00',
            ]), $auth);
            $id = $created->jsonString('id');
            $steps['expiration in utc'] = self::field($created, 'expirationDate');
            $steps['without optional fields'] = $server->json('POST', '/api/sends', self::text(['name' => '2.plain']), $auth);
            $list = $server->send('GET', '/api/sends', $auth);
            $steps['list'] = $list->withBody(CipherTest::sortedByName($list->body));
            $steps['get'] = $server->send('GET', "/api/sends/{$id}", $auth);
            $steps['get unknown'] = $server->send('GET', "/api/sends/{$unknown}", $auth);
            $steps['get invalid id'] = $server->send('GET', '/api/sends/not-a-uuid', $auth);

            $steps['update keeps the password'] = $server->json('PUT', "/api/sends/{$id}", self::text(['name' => '2.renamed', 'text' => ['text' => '2.u'], 'disabled' => true]), $auth);
            $steps['update with password'] = $server->json('PUT', "/api/sends/{$id}", self::text(['password' => 'other']), $auth);
            $steps['change type'] = $server->json('PUT', "/api/sends/{$id}", [...self::text(), 'type' => 1, 'file' => ['fileName' => '2.f']], $auth);
            $steps['update with emails'] = $server->json('PUT', "/api/sends/{$id}", self::text(['emails' => 'a@example.com']), $auth);
            $steps['update without text'] = $server->json('PUT', "/api/sends/{$id}", self::text(['text' => null]), $auth);
            $steps['update far deletion'] = $server->json('PUT', "/api/sends/{$id}", self::text(['deletionDate' => '2099-01-01T00:00:00Z']), $auth);
            $steps['update bad count'] = $server->json('PUT', "/api/sends/{$id}", self::text(['maxAccessCount' => 'x']), $auth);
            $steps['update unknown'] = $server->json('PUT', "/api/sends/{$unknown}", self::text(), $auth);
            $steps['remove password'] = $server->send('PUT', "/api/sends/{$id}/remove-password", $auth);
            $steps['remove password unknown'] = $server->send('PUT', "/api/sends/{$unknown}/remove-password", $auth);

            $steps['file through the text route'] = $server->json('POST', '/api/sends', [...self::text(), 'type' => 1, 'file' => ['fileName' => '2.f']], $auth);
            $steps['invalid type'] = $server->json('POST', '/api/sends', [...self::text(), 'type' => 5], $auth);
            $steps['no text'] = $server->json('POST', '/api/sends', self::text(['text' => null]), $auth);
            $steps['text a string'] = $server->json('POST', '/api/sends', self::text(['name' => '2.string', 'text' => '2.just-a-string']), $auth);
            $steps['far deletion'] = $server->json('POST', '/api/sends', self::text(['deletionDate' => '2099-01-01T00:00:00Z']), $auth);
            $steps['emails'] = $server->json('POST', '/api/sends', self::text(['emails' => 'a@example.com']), $auth);
            $steps['count not a number'] = $server->json('POST', '/api/sends', self::text(['maxAccessCount' => 'x']), $auth);
            $steps['count too large'] = $server->json('POST', '/api/sends', self::text(['maxAccessCount' => 2_147_483_648]), $auth);
            $steps['count a float'] = $server->json('POST', '/api/sends', self::text(['maxAccessCount' => 1.5]), $auth);
            $steps['date not a date'] = $server->json('POST', '/api/sends', self::text(['deletionDate' => 'tomorrow']), $auth);
            $steps['date without offset'] = $server->json('POST', '/api/sends', self::text(['deletionDate' => '2026-11-01T00:00:00']), $auth);
            $steps['no disabled'] = $server->json('POST', '/api/sends', array_diff_key(self::text(), ['disabled' => true]), $auth);

            $steps['delete'] = $server->send('DELETE', "/api/sends/{$id}", $auth);
            $steps['delete again'] = $server->send('DELETE', "/api/sends/{$id}", $auth);
            $list = $server->send('GET', '/api/sends', $auth);
            $steps['list after all'] = $list->withBody(CipherTest::sortedByName($list->body));

            return $steps;
        });
    }

    #[Parity('route:POST /api/sends/access')]
    public function test_access_through_the_link(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, 'send-access@example.com');
            $steps = [];

            $limited = $server->json('POST', '/api/sends', self::text(['maxAccessCount' => 2]), $auth)->jsonString('accessId');
            $steps['token'] = $token = self::token($server, $limited);
            $access = ['Authorization' => 'Bearer '.$token->jsonString('access_token'), 'Accept' => 'application/json'];
            $steps['access'] = $server->send('POST', '/api/sends/access', $access);
            $steps['second access'] = $server->send('POST', '/api/sends/access', $access);
            $steps['third access'] = $server->send('POST', '/api/sends/access', $access);
            $steps['token after the limit'] = self::token($server, $limited);

            $protected = $server->json('POST', '/api/sends', self::text(['password' => 'secret-hash', 'hideEmail' => true]), $auth)->jsonString('accessId');
            $steps['no password'] = self::token($server, $protected);
            $steps['wrong password'] = self::token($server, $protected, 'wrong');
            $steps['right password'] = $right = self::token($server, $protected, 'secret-hash');
            $steps['hidden email'] = $server->send('POST', '/api/sends/access', ['Authorization' => 'Bearer '.$right->jsonString('access_token')]);

            $disabled = $server->json('POST', '/api/sends', self::text(['disabled' => true]), $auth)->jsonString('accessId');
            $steps['disabled'] = self::token($server, $disabled);
            $expired = $server->json('POST', '/api/sends', self::text(['expirationDate' => '2020-01-01T00:00:00Z']), $auth)->jsonString('accessId');
            $steps['expired'] = self::token($server, $expired);

            $steps['unknown access id'] = self::token($server, 'qqqqqqqqS8yNnd7u7u7u7g');
            $steps['not an access id'] = self::token($server, 'not-an-access-id');
            $steps['padded access id'] = self::token($server, $limited.'==');
            $steps['no send id'] = $server->form('/identity/connect/token', ['grant_type' => 'send_access', 'client_id' => 'send']);
            $steps['no client id'] = $server->form('/identity/connect/token', ['grant_type' => 'send_access', 'send_id' => $limited]);
            $steps['two send ids'] = $server->send('POST', '/identity/connect/token', ['Content-Type' => 'application/x-www-form-urlencoded'],
                'grant_type=send_access&client_id=send&send_id='.$limited.'&send_id='.$limited);
            $steps['access without token'] = $server->send('POST', '/api/sends/access', ['Accept' => 'application/json']);
            $steps['access with a login token'] = $server->send('POST', '/api/sends/access', $auth);

            return $steps;
        });
    }

    #[Parity('route:POST /api/sends/file/v2')]
    #[Parity('route:POST /api/sends/{send_id}/file/{file_id}')]
    #[Parity('route:POST /api/sends/access/file/{file_id}')]
    #[Parity('route:GET /api/sends/{send_id}/{file_id}')]
    public function test_file_sends(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, 'send-files@example.com');
            $steps = [];

            $steps['create'] = $created = $server->json('POST', '/api/sends/file/v2', self::file('2.iv/x|ct+y/z==', '11'), $auth);
            $id = $created->jsonString('sendResponse.id');
            $fileId = $created->jsonString('sendResponse.file.id');
            $upload = "/api/sends/{$id}/file/{$fileId}";

            $steps['wrong name'] = $server->multipart($upload, [['data', 'hello world', '2.other']], $auth);
            $steps['bare name'] = $server->multipart($upload, [['data', 'hello world', 'z==']], $auth);
            $steps['wrong size'] = $server->multipart($upload, [['data', 'hello', '2.iv/x|ct+y/z==']], $auth);
            $steps['wrong file id'] = $server->multipart("/api/sends/{$id}/file/0123", [['data', 'hello world', '2.iv/x|ct+y/z==']], $auth);
            $steps['a value'] = $server->multipart($upload, [['data', 'hello world']], $auth);
            $steps['no data'] = $server->multipart($upload, [['key', '2.k']], $auth);
            $steps['as json'] = $server->json('POST', $upload, ['data' => 'x'], $auth);
            $steps['upload'] = $server->multipart($upload, [['data', 'hello world', '2.iv/x|ct+y/z==']], $auth);
            $steps['upload again'] = $server->multipart($upload, [['data', 'hello world', '2.iv/x|ct+y/z==']], $auth);

            $token = self::token($server, $created->jsonString('sendResponse.accessId'))->jsonString('access_token');
            $access = ['Authorization' => "Bearer {$token}", 'Accept' => 'application/json'];
            $steps['access'] = $server->send('POST', '/api/sends/access', $access);
            $steps['access other file'] = $server->send('POST', '/api/sends/access/file/0123', $access);
            $steps['access invalid file id'] = $server->send('POST', '/api/sends/access/file/not_an_id', $access);
            $steps['access file'] = $file = $server->send('POST', "/api/sends/access/file/{$fileId}", $access);
            $steps['access file without token'] = $server->send('POST', "/api/sends/access/file/{$fileId}", ['Accept' => 'application/json']);
            $steps['send after the download link'] = $server->send('GET', "/api/sends/{$id}", $auth);

            $url = (string) parse_url($file->jsonString('url'), PHP_URL_PATH);
            $query = (string) parse_url($file->jsonString('url'), PHP_URL_QUERY);
            $steps['download'] = $server->send('GET', "{$url}?{$query}");
            $steps['download without token'] = $server->send('GET', $url);
            $steps['download with a bad token'] = $server->send('GET', "{$url}?t=nope");
            $steps['download another file'] = $server->send('GET', "/api/sends/{$id}/0123?{$query}");

            $text = $server->json('POST', '/api/sends', self::text(), $auth)->jsonString('accessId');
            $textToken = self::token($server, $text)->jsonString('access_token');
            $steps['file of a text send'] = $server->send('POST', "/api/sends/access/file/{$fileId}", ['Authorization' => "Bearer {$textToken}"]);

            $steps['text through the file route'] = $server->json('POST', '/api/sends/file/v2', self::text(), $auth);
            $steps['no length'] = $server->json('POST', '/api/sends/file/v2', array_diff_key(self::file('2.f', 1), ['fileLength' => true]), $auth);
            $steps['negative length'] = $server->json('POST', '/api/sends/file/v2', self::file('2.f', -1), $auth);
            $steps['too long'] = $server->json('POST', '/api/sends/file/v2', self::file('2.f', 550_502_401), $auth);
            $steps['length a float'] = $server->json('POST', '/api/sends/file/v2', self::file('2.f', 1.5), $auth);
            // Vaultwarden acb574b7: file data that is no object is refused.
            $steps['file a string'] = $server->json('POST', '/api/sends/file/v2', [...self::file('2.f', 1), 'file' => '2.just-a-string'], $auth);
            $steps['file a list'] = $server->json('POST', '/api/sends/file/v2', [...self::file('2.f', 1), 'file' => ['2.f']], $auth);
            $steps['sends after refused files'] = $server->send('GET', '/api/sends', $auth);

            $steps['delete'] = $server->send('DELETE', "/api/sends/{$id}", $auth);
            $steps['download after the delete'] = $server->send('GET', "{$url}?{$query}");

            return $steps;
        });
    }

    /**
     * @param  array<string, mixed>  $changes
     * @return array<string, mixed>
     */
    public static function text(array $changes = []): array
    {
        return [
            'type' => 0,
            'key' => '2.key',
            'name' => '2.name',
            'text' => ['text' => '2.t', 'hidden' => false],
            'deletionDate' => gmdate('Y-m-d\TH:i:s\Z', time() + 7 * 86400),
            'disabled' => false,
            ...$changes,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function file(string $fileName, int|float|string $length): array
    {
        return [...self::text(), 'type' => 1, 'text' => null, 'file' => ['fileName' => $fileName], 'fileLength' => $length];
    }

    private static function token(Server $server, string $accessId, ?string $password = null): Exchange
    {
        return $server->form('/identity/connect/token', array_filter(
            ['grant_type' => 'send_access', 'client_id' => 'send', 'send_id' => $accessId, 'password_hash_b64' => $password],
            static fn (?string $value): bool => $value !== null,
        ));
    }

    /**
     * One value, spelled so that no placeholder replaces it.
     */
    private static function field(Exchange $exchange, string $path): Exchange
    {
        return $exchange->withBody((string) json_encode(['value' => strtr((string) json_encode($exchange->json($path)), '-:T', '   ')]));
    }
}
