<?php

namespace App\Auth;

use App\Config\Config;
use App\Support\IpNetwork;
use Illuminate\Http\Request;

/**
 * The client's address (auth::ClientIp): the IP_HEADER, but only when the
 * request comes from a trusted proxy, otherwise the remote address.
 */
final class ClientIp
{
    public static function resolve(Request $request, Config $config): string
    {
        $remote = self::remoteAddress($request);
        $header = $config->string('ip_header');

        $ip = null;
        if ($config->bool('_ip_header_enabled') && self::isTrusted($remote, $config)) {
            $values = $request->headers->all(strtolower($header));
            $ip = self::fromHeaderValues($values, static fn (string $ip): bool => self::isTrusted($ip, $config));
        }

        return $ip ?? $remote ?? '0.0.0.0';
    }

    /**
     * The rightmost entry of the header that is not a trusted proxy; the
     * leftmost one when they all are. Stops at the first malformed entry.
     *
     * @param  list<string|null>  $values  Every occurrence of the header
     * @param  callable(string): bool  $isTrusted
     */
    public static function fromHeaderValues(array $values, callable $isTrusted): ?string
    {
        $entries = [];
        foreach ($values as $value) {
            foreach (explode(',', (string) $value) as $entry) {
                $entries[] = trim($entry);
            }
        }

        $client = null;
        foreach (array_reverse($entries) as $entry) {
            $ip = self::canonical($entry);
            if ($ip === null) {
                if (app()->bound('log')) {
                    logger()->warning("Client IP header is malformed: {$entry}");
                }

                break;
            }
            $client = $ip;
            if (! $isTrusted($ip)) {
                break;
            }
        }

        return $client;
    }

    /**
     * ip_header_is_trusted: "all", "local" or a list of addresses and ranges.
     * Vaultwarden takes "local" as any non-global address; here it is only
     * where a proxy can run (IpNetwork::LOCAL_PROXY_RANGES), since the web
     * server in front of PHP is often the only one and passes the client's
     * own header on.
     */
    public static function isTrusted(?string $remote, Config $config): bool
    {
        $trusted = trim($config->string('ip_header_trusted_proxies'));
        if (strcasecmp($trusted, 'all') === 0) {
            return true;
        }
        if ($remote === null) {
            return false;
        }

        // IPv4 clients of a dual stack listener arrive as IPv4-mapped IPv6 addresses.
        $remote = IpNetwork::toCanonical($remote);
        if (strcasecmp($trusted, 'local') === 0) {
            return IpNetwork::isLocalProxy($remote);
        }

        foreach (explode(',', $trusted) as $entry) {
            if (IpNetwork::parse($entry)?->contains($remote)) {
                return true;
            }
        }

        return false;
    }

    private static function remoteAddress(Request $request): ?string
    {
        $remote = $request->server('REMOTE_ADDR');

        return is_string($remote) ? self::canonical($remote) : null;
    }

    /**
     * An address as Rust displays it, or null when it is none.
     */
    private static function canonical(string $ip): ?string
    {
        $binary = filter_var($ip, FILTER_VALIDATE_IP) === false ? false : inet_pton($ip);

        return $binary === false ? null : (inet_ntop($binary) ?: null);
    }
}
