<?php

namespace Tests\Feature\Api;

use Illuminate\Support\Facades\DB;
use Tests\Attributes\Parity;
use Tests\TestCase;

/**
 * The simple routes of src/api/web.rs and src/api/core/mod.rs.
 */
class CoreRoutesTest extends TestCase
{
    private const string DATE = '/^"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z"$/';

    #[Parity('route:GET /alive')]
    #[Parity('route:GET /api/alive')]
    #[Parity('route:GET /api/now')]
    public function test_alive_and_now_answer_the_current_time(): void
    {
        foreach (['/alive', '/api/alive', '/api/now'] as $path) {
            $response = $this->get($path)->assertStatus(200)->assertHeader('Content-Type', 'application/json');

            $this->assertMatchesRegularExpression(self::DATE, (string) $response->getContent(), $path);
        }
    }

    #[Parity('route:HEAD /alive')]
    public function test_head_alive_is_empty(): void
    {
        $this->call('HEAD', '/alive')->assertStatus(200)->assertContent('')->assertHeaderMissing('Content-Type');
    }

    #[Parity('route:GET /api/version')]
    public function test_version(): void
    {
        $this->get('/api/version')->assertStatus(200)->assertContent('"1.37.5"');
    }

    public function test_alive_needs_the_database(): void
    {
        config(['database.connections.sqlite.database' => '/nonexistent/folder/db.sqlite3']);
        $this->app->forgetInstance('db');
        DB::clearResolvedInstances();

        $this->get('/alive', ['Accept' => 'application/json'])->assertStatus(503)->assertJsonPath('error.code', 503);
    }
}
