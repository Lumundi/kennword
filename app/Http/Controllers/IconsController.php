<?php

namespace App\Http\Controllers;

use App\Auth\ClientIp;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Cached;
use App\Http\HttpStatus;
use App\Http\Redirect;
use App\Icons\IconService;
use App\Support\EscapeDebug;
use App\Support\HttpClient;
use App\Support\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;

/**
 * src/api/icons.rs: one of the two routes is mounted, depending on ICON_SERVICE.
 */
final readonly class IconsController
{
    public function __construct(
        private Config $config,
        private IconService $icons,
        private RateLimiter $rateLimiter,
    ) {}

    /**
     * routes(): whether Vaultwarden fetches the icons itself.
     */
    public static function internal(Config $config): bool
    {
        return $config->string('icon_service') === 'internal';
    }

    /**
     * GET /icons/<host>/icon.png with an external ICON_SERVICE: a redirect
     * to the icon there. AppHeaders leaves out Cross-Origin-Resource-Policy
     * for this route, which would break the icons in the clients.
     */
    public function iconExternal(string $host): Redirect
    {
        $valid = HttpClient::validHost($host);
        if ($valid === null) {
            Log::warning('Invalid host: '.EscapeDebug::of($host));

            throw new HttpStatus(404, 'Invalid host');
        }
        if (HttpClient::blockReason($valid) !== null) {
            Log::warning("Blocked address: {$valid}");

            throw new HttpStatus(404, 'Blocked address');
        }

        $url = str_replace('{}', $valid, $this->config->string('_icon_service_url'));
        $code = $this->config->int('icon_redirect_code');
        if (! in_array($code, [301, 302, 307, 308], true)) {
            Log::error("Unexpected redirect code {$code}");

            throw new HttpStatus(404, 'Unexpected redirect code');
        }

        return Cached::ttl(new Redirect($url, $code), $this->config->int('icon_cache_ttl'), immutable: true);
    }

    /**
     * GET /icons/<host>/icon.png with the internal ICON_SERVICE: the icon of
     * the host, or the fallback icon, which is cached for ICON_CACHE_NEGTTL.
     */
    public function iconInternal(Request $request, string $host): Response
    {
        $valid = HttpClient::validHost($host);
        if ($valid === null) {
            Log::warning('Invalid host: '.EscapeDebug::of($host));

            return $this->fallback();
        }
        if (HttpClient::blockReason($valid) !== null) {
            Log::warning("Blocked address: {$valid}");

            return $this->fallback();
        }

        // Every download holds a worker, and the route needs no login: one address may start only so many.
        // Cached icons and remembered failures are not counted. The fallback it gets instead is not cached.
        try {
            $icon = $this->icons->icon($valid, fn () => $this->rateLimiter->check('icons', ClientIp::resolve($request, $this->config)));
        } catch (ApiError) {
            Log::warning('Too many icon downloads from one address, answering with the fallback icon');

            return $this->fallback(cached: false);
        }
        if ($icon === null) {
            return $this->fallback();
        }

        return Cached::ttl(new Response($icon[0], 200, ['Content-Type' => "image/{$icon[1]}"]), $this->config->int('icon_cache_ttl'), immutable: true);
    }

    private function fallback(bool $cached = true): Response
    {
        $icon = (string) file_get_contents(resource_path('vaultwarden/static/images/fallback-icon.png'));
        if (! $cached) {
            return new Response($icon, 200, ['Content-Type' => 'image/png', 'Cache-Control' => 'no-store']);
        }

        return Cached::ttl(new Response($icon, 200, ['Content-Type' => 'image/png']), $this->config->int('icon_cache_negttl'), immutable: true);
    }
}
