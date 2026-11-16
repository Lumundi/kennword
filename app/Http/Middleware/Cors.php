<?php

namespace App\Http\Middleware;

use App\Config\Config;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Vaultwarden's CORS handling (util::Cors): only its own origin and the
 * clients' file origins are allowed, and every OPTIONS request is answered
 * as a successful preflight. Unlike Vaultwarden, every response says that
 * it depends on the Origin header, so that caches keep the answers for
 * different origins apart.
 */
final readonly class Cors
{
    public function __construct(
        private Config $config,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $response->setVary('Origin', replace: false);

        $origin = $this->allowedOrigin((string) $request->headers->get('Origin'));
        if ($origin !== null) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
        }

        if ($request->getMethod() === 'OPTIONS') {
            $response->headers->set('Access-Control-Allow-Methods', (string) $request->headers->get('Access-Control-Request-Method'));
            $response->headers->set('Access-Control-Allow-Headers', (string) $request->headers->get('Access-Control-Request-Headers'));
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
            // Laravel's automatic OPTIONS response lists the allowed methods, Rocket's does not.
            $response->headers->remove('Allow');
            $response->setStatusCode(200);
            $response->headers->set('Content-Type', 'text/plain; charset=utf-8');
            $response->setContent('');
        }

        return $response;
    }

    private function allowedOrigin(string $origin): ?string
    {
        $allowed = $origin === $this->config->string('domain_origin')
            // Safari extension and desktop app
            || $origin === 'file://'
            || $origin === 'bw-desktop-file://bundle'
            || ($this->config->bool('sso_enabled') && $origin === $this->config->string('sso_authority'));

        return $allowed ? $origin : null;
    }
}
