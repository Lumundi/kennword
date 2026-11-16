<?php

namespace Tests\Feature\Http;

use Tests\Attributes\Parity;
use Tests\TestCase;

/**
 * util::AppHeaders and util::Cors.
 */
#[Parity('config:DOMAIN')]
#[Parity('config:ALLOWED_IFRAME_ANCESTORS')]
#[Parity('config:ALLOWED_CONNECT_SRC')]
class ResponseHeadersTest extends TestCase
{
    protected function vaultwardenEnvironment(): array
    {
        return [
            'DOMAIN' => 'https://vault.example.com',
            'ALLOWED_IFRAME_ANCESTORS' => 'https://intranet.example.com',
            'ICON_SERVICE' => 'duckduckgo',
        ];
    }

    public function test_security_headers_are_added_to_every_response(): void
    {
        $response = $this->get('/api/now');

        $response->assertHeader('Referrer-Policy', 'same-origin')
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('X-Robots-Tag', 'noindex, nofollow')
            ->assertHeader('X-XSS-Protection', '0')
            ->assertHeader('X-Frame-Options', 'SAMEORIGIN')
            ->assertHeader('Cross-Origin-Resource-Policy', 'same-origin')
            ->assertHeader('Cache-Control', 'max-age=0, no-cache, no-store, private')
            ->assertHeader('Content-Security-Policy', "default-src 'none'; font-src 'self'; manifest-src 'self'; base-uri 'self'; "
                ."form-action 'self'; media-src 'self'; object-src 'self' blob:; script-src 'self' 'wasm-unsafe-eval'; "
                ."style-src 'self' 'unsafe-inline'; child-src 'self' https://*.duosecurity.com https://*.duofederal.com; "
                ."frame-src 'self' https://*.duosecurity.com https://*.duofederal.com; frame-ancestors 'self' "
                .'chrome-extension://nngceckbapebfimnlniiiahkandclblb chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh '
                ."moz-extension://* https://intranet.example.com; img-src 'self' data: https://haveibeenpwned.com "
                ."https://icons.duckduckgo.com/ip3/; connect-src 'self' https://api.pwnedpasswords.com https://api.2fa.directory "
                .'https://app.simplelogin.io/api/ https://app.addy.io/api/ https://api.fastmail.com/ https://api.forwardemail.net ;');

        $this->assertStringStartsWith('accelerometer=(), ambient-light-sensor=()', (string) $response->headers->get('Permissions-Policy'));
    }

    public function test_error_responses_get_the_headers_too(): void
    {
        $this->get('/api/no-such-thing')->assertStatus(404)->assertHeader('X-Frame-Options', 'SAMEORIGIN');
    }

    public function test_only_vaultwardens_own_origin_is_allowed(): void
    {
        $this->get('/api/now', ['Origin' => 'https://vault.example.com'])
            ->assertHeader('Access-Control-Allow-Origin', 'https://vault.example.com');
        $this->get('/api/now', ['Origin' => 'bw-desktop-file://bundle'])
            ->assertHeader('Access-Control-Allow-Origin', 'bw-desktop-file://bundle');
        $this->get('/api/now', ['Origin' => 'https://evil.example.com'])
            ->assertHeaderMissing('Access-Control-Allow-Origin');
    }

    public function test_every_response_varies_by_origin(): void
    {
        // Unlike Vaultwarden: caches must not hand the answer for one origin to another.
        $this->get('/api/now', ['Origin' => 'https://vault.example.com'])->assertHeader('Vary', 'Origin');
        $this->get('/api/now', ['Origin' => 'https://evil.example.com'])->assertHeader('Vary', 'Origin');
        $this->get('/api/now')->assertHeader('Vary', 'Origin');
        $this->get('/api/no-such-thing')->assertStatus(404)->assertHeader('Vary', 'Origin');
        $this->call('OPTIONS', '/api/accounts/profile', server: ['HTTP_ORIGIN' => 'https://vault.example.com'])->assertHeader('Vary', 'Origin');
    }

    public function test_every_options_request_is_a_successful_preflight(): void
    {
        $response = $this->call('OPTIONS', '/api/accounts/profile', server: [
            'HTTP_ORIGIN' => 'https://vault.example.com',
            'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'PUT',
            'HTTP_ACCESS_CONTROL_REQUEST_HEADERS' => 'authorization,content-type',
        ]);

        $response->assertStatus(200)
            ->assertContent('')
            ->assertHeader('Content-Type', 'text/plain; charset=utf-8')
            ->assertHeader('Access-Control-Allow-Origin', 'https://vault.example.com')
            ->assertHeader('Access-Control-Allow-Methods', 'PUT')
            ->assertHeader('Access-Control-Allow-Headers', 'authorization,content-type')
            ->assertHeader('Access-Control-Allow-Credentials', 'true')
            ->assertHeaderMissing('Allow');
    }
}
