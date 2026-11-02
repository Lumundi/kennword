<?php

namespace App\Http\Controllers;

use App\Auth\ClientIp;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\LoginClaims;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Data\Query;
use App\Http\HttpStatus;
use App\Notifications\Subscriptions;
use App\Notifications\WebSocketAccept;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Throwable;

/**
 * src/api/notifications.rs: the SignalR hubs. Only the notifications daemon
 * (php artisan kennword:notifications) can keep a WebSocket open; it
 * passes the upgrade requests through these handlers and takes over the
 * connection when they accept it. Requests that reach PHP otherwise are
 * answered as if WebSockets were disabled.
 */
final class NotificationsController
{
    /**
     * GET /notifications/hub
     */
    public function websocketsHub(Request $request, Config $config, Jwt $jwt): WebSocketAccept
    {
        self::subscriptions();
        $acceptKey = self::acceptKey($request, $config);
        $ip = ClientIp::resolve($request, $config);
        $headerToken = self::headerToken($request);
        $queryToken = Query::first($request, 'access_token');

        logger()->info("Accepting WS connection from {$ip}");

        $token = $queryToken ?? $headerToken ?? throw ApiError::message('Invalid claim', 401);

        try {
            $claims = LoginClaims::fromArray($jwt->decode($token, JwtIssuer::Login));
        } catch (Throwable) {
            $claims = null;
        }
        if ($claims === null) {
            throw ApiError::message('Invalid token', 401);
        }

        return new WebSocketAccept($acceptKey, $ip, userId: $claims->sub);
    }

    /**
     * GET /notifications/anonymous-hub
     */
    public function anonymousWebsocketsHub(Request $request, Config $config): WebSocketAccept
    {
        $subscriptions = self::subscriptions();
        $acceptKey = self::acceptKey($request, $config);
        $ip = ClientIp::resolve($request, $config);
        // `?<token..>` as a String: the value of the first field, whatever its name.
        $token = self::firstQueryValue($request) ?? self::forward($config, 422, 'The query has no token.');

        logger()->info("Accepting Anonymous WS connection from {$ip}");

        if (! $subscriptions->tryReserve($ip)) {
            throw ApiError::message('Too many connections', 429);
        }

        return new WebSocketAccept($acceptKey, $ip, anonymousToken: $token);
    }

    /**
     * The daemon's subscriptions; without the daemon the hubs do not exist.
     */
    private static function subscriptions(): Subscriptions
    {
        if (! app()->bound(Subscriptions::class)) {
            throw new NotFoundHttpException('WebSocket requests are served by the notifications daemon.');
        }

        return app(Subscriptions::class);
    }

    /**
     * Rocket tries the next route, the web vault's catch-all, which knows no
     * such file; without the web vault the forward's status is answered.
     *
     * @throws HttpStatus
     */
    private static function forward(Config $config, int $status, string $reason): never
    {
        throw new HttpStatus(WebController::webVaultEnabled($config) ? 404 : $status, $reason);
    }

    /**
     * rocket_ws' WebSocket guard: an upgrade to WebSocket version 13 with a
     * key, else the request is forwarded with 400.
     */
    private static function acceptKey(Request $request, Config $config): string
    {
        $hasToken = static function (string $header, string $token) use ($request): bool {
            foreach ($request->headers->all($header) as $value) {
                foreach (explode(',', (string) $value) as $part) {
                    if (strcasecmp(trim($part), $token) === 0) {
                        return true;
                    }
                }
            }

            return false;
        };

        $key = $request->headers->get('Sec-WebSocket-Key');
        if ($key === null || ! $hasToken('Connection', 'upgrade') || ! $hasToken('Upgrade', 'websocket')
            || $request->headers->get('Sec-WebSocket-Version') !== '13') {
            self::forward($config, 400, 'Not a WebSocket upgrade.');
        }

        return base64_encode(sha1($key.'258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
    }

    /**
     * auth::WsAccessTokenHeader: everything after the last "Bearer " of the
     * Authorization header, or all of it.
     */
    private static function headerToken(Request $request): ?string
    {
        $authorization = $request->headers->get('Authorization');
        if ($authorization === null) {
            return null;
        }
        $position = strrpos($authorization, 'Bearer ');

        return $position === false ? $authorization : substr($authorization, $position + strlen('Bearer '));
    }

    private static function firstQueryValue(Request $request): ?string
    {
        $query = $request->server->get('QUERY_STRING');
        foreach (explode('&', is_string($query) ? $query : '') as $pair) {
            if ($pair !== '') {
                return urldecode(array_pad(explode('=', $pair, 2), 2, '')[1]);
            }
        }

        return null;
    }
}
