<?php

namespace App\Notifications;

/**
 * WS_USERS and WS_ANONYMOUS_SUBSCRIPTIONS of src/api/notifications.rs: the
 * open hub connections of the notifications daemon, by user and by auth
 * request token, and how many anonymous connections each address holds.
 */
final class Subscriptions
{
    /**
     * The anonymous hub needs no authentication, so bound how much a single
     * client can hold open. One connection is needed per pending login
     * request, several at once are only expected behind NAT.
     */
    public const int MAX_ANONYMOUS_CONNECTIONS_PER_IP = 25;

    /**
     * Vaultwarden has no limit for all addresses together, but tokio holds as many connections as
     * the system allows. The daemon holds Server::MAX_CONNECTIONS; anonymous ones, whose
     * addresses cost little to come by in IPv6, may take a quarter of them.
     */
    public const int MAX_ANONYMOUS_CONNECTIONS = Server::MAX_CONNECTIONS / 4;

    /**
     * An account needs a connection per device and open web vault. Vaultwarden has no limit; past
     * this, the account's oldest connection makes way, so that one account cannot take all of
     * Server::MAX_CONNECTIONS from everybody else.
     */
    public const int MAX_CONNECTIONS_PER_USER = 50;

    /**
     * @var array<string, array<int, WebSocketConnection>>
     */
    private array $users = [];

    /**
     * @var array<string, array<int, WebSocketConnection>>
     */
    private array $anonymous = [];

    /**
     * @var array<string, int>
     */
    private array $anonymousConnections = [];

    /**
     * Takes a connection slot for this address, false when it or all addresses together already reached the limit.
     */
    public function tryReserve(string $ip): bool
    {
        $count = $this->anonymousConnections[$ip] ?? 0;
        if ($count >= self::MAX_ANONYMOUS_CONNECTIONS_PER_IP || array_sum($this->anonymousConnections) >= self::MAX_ANONYMOUS_CONNECTIONS) {
            return false;
        }
        $this->anonymousConnections[$ip] = $count + 1;

        return true;
    }

    /**
     * Releases a slot taken by tryReserve.
     */
    public function release(string $ip): void
    {
        $count = ($this->anonymousConnections[$ip] ?? 0) - 1;
        if ($count > 0) {
            $this->anonymousConnections[$ip] = $count;
        } else {
            unset($this->anonymousConnections[$ip]);
        }
    }

    public function subscribe(WebSocketConnection $connection): void
    {
        if ($connection->userId !== null) {
            $this->users[$connection->userId][$connection->id] = $connection;
        }
        if ($connection->anonymousToken !== null) {
            // Clients reconnect with the same token while a login request is still pending,
            // so every subscriber is kept.
            $this->anonymous[$connection->anonymousToken][$connection->id] = $connection;
        }
    }

    /**
     * WSEntryMapGuard and WSAnonymousEntryMapGuard: once the connection is closed.
     */
    public function unsubscribe(WebSocketConnection $connection): void
    {
        if ($connection->userId !== null) {
            unset($this->users[$connection->userId][$connection->id]);
            if (($this->users[$connection->userId] ?? []) === []) {
                unset($this->users[$connection->userId]);
            }
        }
        if ($connection->anonymousToken !== null) {
            unset($this->anonymous[$connection->anonymousToken][$connection->id]);
            if (($this->anonymous[$connection->anonymousToken] ?? []) === []) {
                unset($this->anonymous[$connection->anonymousToken]);
            }
            $this->release($connection->ip);
        }
    }

    /**
     * @return list<WebSocketConnection>
     */
    public function ofUser(string $userId): array
    {
        return array_values($this->users[$userId] ?? []);
    }

    /**
     * @return list<WebSocketConnection>
     */
    public function ofToken(string $token): array
    {
        return array_values($this->anonymous[$token] ?? []);
    }

    public function count(): int
    {
        return array_sum(array_map(count(...), $this->users)) + array_sum(array_map(count(...), $this->anonymous));
    }
}
