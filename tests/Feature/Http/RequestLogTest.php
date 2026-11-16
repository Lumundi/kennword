<?php

namespace Tests\Feature\Http;

use App\Support\Random;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * Vaultwarden logs a line for each request (util::BetterLogging) and leaves
 * out the values of its query since #7929 (82fc47e, after the pin), because
 * they can hold secrets. Kennword leaves that line to the web server
 * (docs/installation.md shows access log formats without the query), so the
 * secrets of a query stay out of its own log, also when the request fails.
 */
class RequestLogTest extends TestCase
{
    use UsesVaultwardenDatabase;

    protected function vaultwardenEnvironment(): array
    {
        return ['LOG_LEVEL' => 'trace'];
    }

    public function test_query_values_stay_out_of_the_log(): void
    {
        $this->useDatabase('sqlite');
        $messages = [];
        Event::listen(MessageLogged::class, static function (MessageLogged $event) use (&$messages): void {
            $messages[] = $event->message.' '.json_encode($event->context);
        });

        $id = Random::uuid();
        $this->get("/api/auth-requests/{$id}/response?code=secret-access-code", ['Device-Type' => '10'])->assertStatus(400);
        $this->get("/attachments/{$id}/".str_repeat('a', 20).'?token=secret-download-token')->assertStatus(404);
        // Like Vaultwarden's error, the log names a state it cannot read.
        $this->get('/identity/connect/oidc-signin?code=secret-sso-code&state=unreadable')->assertStatus(400);
        $this->get('/api/now?secret-flag&name=secret-value')->assertStatus(200);

        $this->assertNotSame([], $messages, 'The errors are logged');
        foreach ($messages as $message) {
            $this->assertStringNotContainsString('secret', $message);
        }
    }
}
