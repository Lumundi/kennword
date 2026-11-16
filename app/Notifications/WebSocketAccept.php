<?php

namespace App\Notifications;

use Symfony\Component\HttpFoundation\Response;

/**
 * The 101 answer of a hub (rocket_ws' MessageStream responder). The
 * notifications daemon sends it and then speaks WebSocket on the connection,
 * subscribed to the user's updates or to the auth request token.
 */
final class WebSocketAccept extends Response
{
    /**
     * @param  int|null  $validUntil  The last second (UNIX time) in which the access token is valid;
     *                                the daemon closes the connection after it
     */
    public function __construct(
        string $acceptKey,
        public readonly string $ip,
        public readonly ?string $userId = null,
        public readonly ?string $anonymousToken = null,
        public readonly ?int $validUntil = null,
    ) {
        parent::__construct('', 101, [
            'Sec-Websocket-Version' => '13',
            'Sec-WebSocket-Accept' => $acceptKey,
            'Connection' => 'upgrade',
            'Upgrade' => 'websocket',
        ]);
    }
}
