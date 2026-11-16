<?php

namespace App\Support;

/**
 * An IP address or CIDR range like Rust's IpNet.
 */
final readonly class IpNetwork
{
    /**
     * Where a reverse proxy in front of us can run: loopback, the private
     * networks of RFC 1918 and RFC 4193, link-local addresses and the shared
     * address space of carrier-grade NAT and overlay networks (RFC 6598).
     */
    public const array LOCAL_PROXY_RANGES = [
        '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10',
        '::1/128', 'fc00::/7', 'fe80::/10',
    ];

    private function __construct(
        public string $address,
        public int $prefix,
    ) {}

    /**
     * parse_trusted_proxy: a CIDR range, or a single address.
     */
    public static function parse(string $entry): ?self
    {
        $entry = trim($entry);
        [$address, $prefix] = array_pad(explode('/', $entry, 2), 2, null);

        $binary = filter_var($address, FILTER_VALIDATE_IP) === false ? false : inet_pton((string) $address);
        if ($binary === false) {
            return null;
        }

        $bits = strlen($binary) * 8;
        if ($prefix === null) {
            return new self($binary, $bits);
        }
        if (! preg_match('/^[0-9]{1,3}$/D', $prefix) || (int) $prefix > $bits) {
            return null;
        }

        return new self($binary, (int) $prefix);
    }

    /**
     * IpAddr::to_canonical: an IPv4-mapped IPv6 address as IPv4.
     */
    public static function toCanonical(string $ip): string
    {
        $binary = filter_var($ip, FILTER_VALIDATE_IP) === false ? false : inet_pton($ip);
        if ($binary === false || strlen($binary) !== 16 || ! str_starts_with($binary, str_repeat("\0", 10)."\xFF\xFF")) {
            return $ip;
        }

        return (string) inet_ntop(substr($binary, 12));
    }

    /**
     * util::is_global: whether the address is globally reachable.
     */
    public static function isGlobal(string $ip): bool
    {
        $binary = filter_var($ip, FILTER_VALIDATE_IP) === false ? false : inet_pton($ip);
        if ($binary === false) {
            return false;
        }

        $numbers = array_map(
            static fn (mixed $number): int => is_int($number) ? $number : 0,
            array_values(unpack(strlen($binary) === 4 ? 'C4' : 'n8', $binary) ?: []),
        );

        return strlen($binary) === 4 ? self::isGlobalV4($numbers) : self::isGlobalV6($numbers);
    }

    /**
     * Whether the address is in LOCAL_PROXY_RANGES. Narrower than not
     * isGlobal(), which is meant for outgoing requests: tunnel and translation
     * prefixes such as 6to4 (2002::/16), Teredo (2001::/32) or the local-use
     * NAT64 prefix (64:ff9b:1::/48) are not global either, but clients from
     * anywhere can connect from them.
     */
    public static function isLocalProxy(string $ip): bool
    {
        foreach (self::LOCAL_PROXY_RANGES as $range) {
            if (self::parse($range)?->contains($ip)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<int>  $o  Octets
     */
    private static function isGlobalV4(array $o): bool
    {
        $broadcast = $o === [255, 255, 255, 255];

        return ! ($o[0] === 0
            || $o[0] === 10 || ($o[0] === 172 && ($o[1] & 0xF0) === 16) || ($o[0] === 192 && $o[1] === 168)
            || ($o[0] === 100 && ($o[1] & 0b1100_0000) === 0b0100_0000)
            || $o[0] === 127
            || ($o[0] === 169 && $o[1] === 254)
            // Reserved for future protocols, except .9 and .10.
            || ($o[0] === 192 && $o[1] === 0 && $o[2] === 0 && $o[3] !== 9 && $o[3] !== 10)
            || ($o[0] === 192 && $o[1] === 0 && $o[2] === 2) || ($o[0] === 198 && $o[1] === 51 && $o[2] === 100)
            || ($o[0] === 203 && $o[1] === 0 && $o[2] === 113)
            || ($o[0] === 198 && ($o[1] & 0xFE) === 18)
            || (($o[0] & 240) === 240 && ! $broadcast)
            || $broadcast);
    }

    /**
     * @param  list<int>  $s  Segments
     */
    private static function isGlobalV6(array $s): bool
    {
        $ietf = $s[0] === 0x2001 && $s[1] < 0x200
            && ! ($s === [0x2001, 1, 0, 0, 0, 0, 0, 1] || $s === [0x2001, 1, 0, 0, 0, 0, 0, 2]
                || $s[1] === 3 || ($s[1] === 4 && $s[2] === 0x112) || ($s[1] >= 0x20 && $s[1] <= 0x3F));

        return ! ($s === [0, 0, 0, 0, 0, 0, 0, 0]
            || $s === [0, 0, 0, 0, 0, 0, 0, 1]
            || array_slice($s, 0, 6) === [0, 0, 0, 0, 0, 0xFFFF]
            || array_slice($s, 0, 3) === [0x64, 0xFF9B, 1]
            || array_slice($s, 0, 4) === [0x100, 0, 0, 0]
            || $ietf
            || $s[0] === 0x2002
            || ($s[0] === 0x2001 && $s[1] === 0xDB8) || ($s[0] === 0x3FFF && $s[1] <= 0x0FFF)
            || $s[0] === 0x5F00
            || ($s[0] & 0xFE00) === 0xFC00
            || ($s[0] & 0xFFC0) === 0xFE80);
    }

    public function contains(string $ip): bool
    {
        $binary = filter_var($ip, FILTER_VALIDATE_IP) === false ? false : inet_pton($ip);
        if ($binary === false || strlen($binary) !== strlen($this->address)) {
            return false;
        }

        $bytes = intdiv($this->prefix, 8);
        $bits = $this->prefix % 8;
        if (substr($binary, 0, $bytes) !== substr($this->address, 0, $bytes)) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $bits)) & 0xFF;

        return (ord($binary[$bytes]) & $mask) === (ord($this->address[$bytes]) & $mask);
    }
}
