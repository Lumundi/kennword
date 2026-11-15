<?php

namespace Tests\Feature\Http;

use App\Auth\AuthMethod;
use App\Auth\Jwt;
use App\Auth\LoginClaims;
use App\Models\Device;
use App\Models\User;
use App\Support\Random;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * Rocket's Json<T> guard parses with serde_json, which refuses more than 127
 * nested arrays or objects. A deeper document stored in a cipher would make
 * every response that contains the cipher fail to encode.
 */
class JsonBodyTest extends TestCase
{
    use UsesVaultwardenDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');
    }

    public function test_bodies_nested_deeper_than_serde_json_allows_are_refused(): void
    {
        $this->prelogin(127)->assertStatus(200);
        $this->prelogin(128)->assertStatus(400);
    }

    public function test_a_cipher_at_the_nesting_limit_still_syncs(): void
    {
        $user = User::new('nesting@example.com');
        $user->save();
        $device = Device::new(Random::uuid(), $user->uuid, 'cli', 25);
        $device->save();
        $jwt = $this->app->make(Jwt::class);
        $auth = ['Authorization' => 'Bearer '.LoginClaims::default($device, $user, AuthMethod::Password, 'cli', $jwt)->token($jwt)];

        // The body, secureNote and 125 arrays: 127 containers.
        $deep = str_repeat('[', 125).'1'.str_repeat(']', 125);
        $body = '{"type":2,"name":"2.note","encryptedFor":"'.$user->uuid.'","secureNote":{"type":0,"x":'.$deep.'}}';
        $this->call('POST', '/api/ciphers', [], [], [], $this->transformHeadersToServerVars([...$auth, 'Content-Type' => 'application/json']), $body)
            ->assertStatus(200);
        $this->getJson('/api/sync', $auth)->assertStatus(200)->assertJsonCount(1, 'ciphers');

        $tooDeep = str_replace('"x":', '"x":[', $body);
        $tooDeep = substr($tooDeep, 0, -2).']}}';
        $this->call('POST', '/api/ciphers', [], [], [], $this->transformHeadersToServerVars([...$auth, 'Content-Type' => 'application/json']), $tooDeep)
            ->assertStatus(400);
        $this->getJson('/api/sync', $auth)->assertStatus(200)->assertJsonCount(1, 'ciphers');
    }

    /**
     * @return TestResponse<Response>
     */
    private function prelogin(int $containers): TestResponse
    {
        $nested = str_repeat('[', $containers - 1).'1'.str_repeat(']', $containers - 1);

        return $this->call('POST', '/identity/accounts/prelogin', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{"email":"nobody@example.com","x":'.$nested.'}');
    }
}
