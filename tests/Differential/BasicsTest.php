<?php

namespace Tests\Differential;

use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Attributes\Parity;

/**
 * The routes that exist so far, the catchers and the response headers.
 */
class BasicsTest extends DifferentialTestCase
{
    /**
     * @return iterable<string, array{string, string, array<string, string>}>
     */
    public static function requests(): iterable
    {
        yield 'alive' => ['GET', '/alive', []];
        yield 'alive head' => ['HEAD', '/alive', []];
        yield 'api alive' => ['GET', '/api/alive', []];
        yield 'now' => ['GET', '/api/now', []];
        yield 'now head' => ['HEAD', '/api/now', []];
        yield 'version' => ['GET', '/api/version', []];
        yield 'version with query' => ['GET', '/api/version?x=1', []];
        yield 'trailing slash' => ['GET', '/api/version/', []];
        yield 'api not found' => ['GET', '/api/no-such-route', []];
        yield 'api not found for a browser' => ['GET', '/api/no-such-route', ['Accept' => 'text/html']];
        yield 'unmatched method' => ['DELETE', '/api/now', ['Accept' => 'application/json']];
        yield 'not found page' => ['GET', '/no-such-page', []];
        yield 'not found below identity' => ['GET', '/identity/no-such-route', ['Accept' => 'application/json']];
        yield 'not found below admin' => ['GET', '/admin/no/such/route', []];
        yield 'allowed origin' => ['GET', '/api/now', ['Origin' => 'http://localhost']];
        yield 'desktop origin' => ['GET', '/api/now', ['Origin' => 'bw-desktop-file://bundle']];
        yield 'foreign origin' => ['GET', '/api/now', ['Origin' => 'https://evil.example.com']];
        yield 'preflight' => ['OPTIONS', '/api/accounts/profile', [
            'Origin' => 'http://localhost',
            'Access-Control-Request-Method' => 'PUT',
            'Access-Control-Request-Headers' => 'authorization,content-type',
        ]];
        yield 'preflight of an existing route' => ['OPTIONS', '/api/now', ['Origin' => 'http://localhost']];
        yield 'script name in the path' => ['GET', '/index.php/alive', []];
        yield 'script name before admin' => ['GET', '/index.php/admin', []];
        yield 'encoded script name before admin' => ['GET', '/index%2Ephp/admin', []];
        yield 'script name before the api' => ['GET', '/index.php/api/now', ['Accept' => 'application/json']];
        yield 'script name alone' => ['GET', '/index.php', []];
        yield 'method override in the query' => ['POST', '/api/accounts?_method=DELETE', ['Accept' => 'application/json']];
        yield 'method override header' => ['POST', '/api/accounts', ['X-HTTP-Method-Override' => 'DELETE', 'Accept' => 'application/json']];
    }

    public function test_data_limits_and_the_form_method_override(): void
    {
        $this->assertSameFlows(static function (Server $server): array {
            $form = ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json'];

            return [
                'method override as the first field' => $server->send('POST', '/api/accounts', $form, '_method=DELETE'),
                'method override as a later field' => $server->send('POST', '/api/accounts', $form, 'a=1&_method=DELETE'),
                'form over the limit' => $server->send('POST', '/admin', $form, 'token='.str_repeat('a', 32 * 1024)),
                'json over the limit' => $server->send('POST', '/identity/accounts/prelogin', ['Content-Type' => 'application/json', 'Accept' => 'application/json'],
                    str_pad('{"email":"limits@example.com"}', 20_000_001)),
            ];
        });
    }

    /**
     * @param  array<string, string>  $headers
     */
    #[DataProvider('requests')]
    #[Parity('route:GET /alive')]
    #[Parity('route:HEAD /alive')]
    #[Parity('route:GET /api/alive')]
    #[Parity('route:GET /api/now')]
    #[Parity('route:GET /api/version')]
    public function test_responses_match(string $method, string $path, array $headers): void
    {
        $this->assertSameResponses($method, $path, $headers);
    }
}
