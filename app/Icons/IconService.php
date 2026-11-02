<?php

namespace App\Icons;

use App\Config\Config;
use App\Support\BlockedHost;
use App\Support\DataUrl;
use App\Support\EscapeDebug;
use App\Support\HttpClient;
use App\Support\HttpRequestFailed;
use App\Support\HttpResponse;
use Illuminate\Support\Facades\Log;
use Uri\WhatWg\Url;

/**
 * The internal icon service of src/api/icons.rs: the icon of a domain from
 * ICON_CACHE_FOLDER, or downloaded from the site and cached. Failures are
 * remembered too (a ".miss" file), unless a blocked host caused them.
 */
final readonly class IconService
{
    public function __construct(
        private Config $config,
        private IconClient $client,
    ) {}

    /**
     * get_icon: the icon and its image type, or null for the fallback icon.
     *
     * @return array{string, string}|null
     */
    public function icon(string $domain): ?array
    {
        $path = "{$domain}.png";

        if ($this->isNegcached($path)) {
            return null;
        }
        $cached = $this->cachedIcon($path);
        if ($cached !== null) {
            return [$cached, self::iconType($cached) ?? 'x-icon'];
        }
        if ($this->config->bool('disable_icon_download')) {
            return null;
        }

        try {
            [$icon, $type] = $this->downloadIcon($domain);
        } catch (BlockedHost $blocked) {
            // A blocked domain or address: no miss file, which would reveal it.
            Log::warning($blocked->getMessage());

            return null;
        } catch (HttpRequestFailed $failed) {
            Log::warning("Unable to download icon: {$failed->getMessage()}");
            $this->save("{$path}.miss", '');

            return null;
        }
        $this->save($path, $icon);

        return [$icon, $type ?? 'x-icon'];
    }

    /**
     * get_icon_priority: lower is better. Square sizes come first, 32x32
     * best; without a size the file extension counts.
     */
    public static function priority(string $href, string $sizes): int
    {
        [$width, $height] = self::parseSizes($sizes);
        if ($width !== 0 && $height !== 0) {
            if ($width !== $height) {
                return 200;
            }

            return match (true) {
                $width === 32 => 1,
                $width === 64 => 2,
                $width >= 24 && $width <= 192 => 3,
                $width === 16 => 4,
                default => 5,
            };
        }

        $dot = strrpos($href, '.');
        if ($dot === false) {
            return 30;
        }

        return match (strtolower(substr($href, $dot + 1))) {
            'png' => 10,
            'jpg', 'jpeg' => 20,
            default => 30,
        };
    }

    /**
     * parse_sizes: the first two numbers of a sizes attribute like "32x32",
     * or zeros. Numbers that do not fit a u16 are zero.
     *
     * @return array{int, int}
     */
    public static function parseSizes(string $sizes): array
    {
        // Rust's \d matches every Unicode digit, which u16::from_str then refuses.
        if ($sizes === '' || ! mb_check_encoding($sizes, 'UTF-8') || preg_match('/(\p{Nd}+)\P{Nd}*(\p{Nd}+)/u', $sizes, $match) !== 1) {
            return [0, 0];
        }
        $number = static fn (string $digits): int => preg_match('/^[0-9]+$/D', $digits) === 1 && (int) ltrim($digits, '0') <= 0xFFFF && strlen(ltrim($digits, '0')) <= 5
            ? (int) $digits
            : 0;

        return [$number($match[1]), $number($match[2])];
    }

    /**
     * get_icon_type: the image type of the bytes by their signature, or null for anything else.
     */
    public static function iconType(string $bytes): ?string
    {
        return match (true) {
            str_starts_with($bytes, "\x89PNG\r\n\x1A\n") => 'png',
            strlen($bytes) >= 6 && str_starts_with($bytes, "\0\0\1\0") && substr($bytes, 4, 2) !== "\0\0" => 'x-icon',
            strlen($bytes) >= 12 && str_starts_with($bytes, 'RIFF') && substr($bytes, 8, 4) === 'WEBP' => 'webp',
            strlen($bytes) >= 4 && str_starts_with($bytes, "\xFF\xD8\xFF") && ord($bytes[3]) >= 0xC0 => 'jpeg',
            str_starts_with($bytes, 'GIF87a') || str_starts_with($bytes, 'GIF89a') => 'gif',
            strlen($bytes) >= 10 && str_starts_with($bytes, 'BM') && substr($bytes, 6, 4) === "\0\0\0\0" => 'bmp',
            str_starts_with($bytes, '<svg') => 'svg+xml',
            // An SVG after an XML declaration: an svg tag within the first KB, which must be UTF-8.
            str_starts_with($bytes, '<?xml') => mb_check_encoding($head = substr($bytes, 0, 1024), 'UTF-8')
                && (str_contains($head, '<svg') || str_contains($head, '<SVG')) ? 'svg+xml' : null,
            default => null,
        };
    }

    /**
     * get_icon_url: the candidates for the domain's icon, best first, and
     * the page they come from, for the Referer.
     *
     * @return array{list<array{int, string}>, string}
     */
    public function iconUrls(string $domain): array
    {
        $sslDomain = "https://{$domain}";
        $httpDomain = "http://{$domain}";

        try {
            $page = $this->client->get($sslDomain);
        } catch (BlockedHost $blocked) {
            $page = $blocked;
        } catch (HttpRequestFailed) {
            // Unless the host was blocked, HTTP is next, then the domain without
            // subdomains or with www. in front.
            $page = $this->firstPage([$httpDomain]);
            if ($page instanceof HttpRequestFailed && filter_var($domain, FILTER_VALIDATE_IP) === false) {
                $dots = substr_count($domain, '.');
                $labels = explode('.', $domain);
                $other = $dots > 1 ? implode('.', array_slice($labels, -2)) : "www.{$domain}";
                if (HttpClient::validHost($other) !== null) {
                    $page = $this->firstPage(["https://{$other}", "http://{$other}"]);
                }
            }
        }

        $icons = [];
        $referer = '';
        if ($page instanceof HttpRequestFailed) {
            $icons[] = [35, "{$sslDomain}/favicon.ico"];
            $icons[] = [40, "{$sslDomain}/apple-touch-icon.png"];
            $icons[] = [35, "{$httpDomain}/favicon.ico"];
            $icons[] = [40, "{$httpDomain}/apple-touch-icon.png"];
        } else {
            // The URL after redirects, also as Referer, which some sites check.
            $url = $page->url;
            $referer = $url->toAsciiString();
            $icons[] = [35, (string) Url::parse('/favicon.ico', $url)?->toAsciiString()];
            $icons[] = [40, (string) Url::parse('/apple-touch-icon.png', $url)?->toAsciiString()];
            // 384KB should be more than enough for the HTML, though as we only really need the HTML header.
            $icons = [...$icons, ...self::faviconsInPage($page->read(384 * 1024), $url)];
        }
        usort($icons, static fn (array $a, array $b): int => $a[0] <=> $b[0]);

        return [$icons, $referer];
    }

    /**
     * get_favicons_node: the icon links in the head of the page, with their
     * priorities, resolved against its base.
     *
     * @return list<array{int, string}>
     */
    public static function faviconsInPage(string $html, Url $url): array
    {
        $base = $url;
        $tags = [];
        $tokenizer = new HtmlTokenizer($html);
        while (($token = $tokenizer->next()) !== null) {
            if ($token['name'] === 'link') {
                $tags[] = $token['attributes'];
            } elseif ($token['name'] === 'base') {
                $href = $token['attributes']['href'] ?? null;
                if ($href !== null) {
                    $href = self::utf8OrEmpty($href);
                    Log::debug('Found base href: '.EscapeDebug::of($href));
                    $base = Url::parse($href, $base) ?? $base;
                }
            } elseif ($token['name'] === 'head' && $token['closing']) {
                break;
            }
        }

        $icons = [];
        foreach ($tags as $attributes) {
            $href = isset($attributes['href']) ? Url::parse(self::utf8OrEmpty($attributes['href']), $base) : null;
            if ($href !== null) {
                $full = $href->toAsciiString();
                $icons[] = [self::priority($full, self::utf8OrEmpty($attributes['sizes'] ?? '')), $full];
            }
        }

        return $icons;
    }

    /**
     * download_icon: the first of the five best candidates that is an
     * image, and its type. A broken SVG gives an empty icon without a type.
     *
     * @return array{string, ?string}
     *
     * @throws HttpRequestFailed
     */
    private function downloadIcon(string $domain): array
    {
        [$icons, $referer] = $this->iconUrls($domain);
        $icons = array_slice($icons, 0, 5);

        $buffer = '';
        $type = null;
        foreach ($icons as $index => [, $href]) {
            if (str_starts_with($href, 'data:image')) {
                $body = DataUrl::process($href)?->decode();
                if ($body === null) {
                    Log::debug('Extracted icon from data:image uri is invalid');

                    continue;
                }
                // Also check if the size is at least 67 bytes, which seems to be the smallest png I could create.
                if (strlen($body) >= 67) {
                    $type = self::iconType($body);
                    if ($type === null) {
                        Log::debug("Icon from {$domain} data:image uri, is not a valid image type");

                        continue;
                    }
                    Log::info("Extracted icon from data:image uri for {$domain}");
                    $buffer = $body;

                    break;
                }

                continue;
            }

            Log::debug("Trying {$href}");
            try {
                $response = $this->client->get($href, $referer);
            } catch (HttpRequestFailed $failed) {
                // Make sure all icons are checked before returning an error, unless the host is blocked.
                if ($index === count($icons) - 1 || $failed instanceof BlockedHost) {
                    throw $failed;
                }
                Log::warning("Unable to download icon: {$failed->getMessage()}");

                continue;
            }
            // 5120KB/5MB for each icon max (Same as icons.bitwarden.net).
            $buffer = $response->read(5120 * 1024);
            $type = self::iconType($buffer);
            if ($type === null) {
                $buffer = '';
                Log::debug("Icon from {$href}, is not a valid image type");

                continue;
            }
            Log::info("Downloaded icon from {$href}");

            break;
        }

        if ($buffer === '') {
            throw new HttpRequestFailed("Empty response or unable find a valid icon for {$domain}");
        }
        if ($type === 'svg+xml') {
            $sanitized = SvgFilter::filter($buffer);
            if ($sanitized === null) {
                return ['', null];
            }
            $buffer = $sanitized;
        }

        return [$buffer, $type];
    }

    /**
     * The first page of the URLs that can be fetched, or the last failure.
     *
     * @param  non-empty-list<string>  $urls
     */
    private function firstPage(array $urls): HttpResponse|HttpRequestFailed
    {
        $failure = null;
        foreach ($urls as $url) {
            try {
                return $this->client->get($url);
            } catch (HttpRequestFailed $failed) {
                $failure = $failed;
            }
        }

        return $failure;
    }

    /**
     * icon_is_negcached: whether a download failed less than ICON_CACHE_NEGTTL ago. An older marker is removed.
     */
    private function isNegcached(string $path): bool
    {
        $marker = "{$path}.miss";
        $expired = $this->isExpired($marker, $this->config->int('icon_cache_negttl'));
        if ($expired === true) {
            if (! @unlink($this->file($marker))) {
                Log::error("Could not remove negative cache indicator for icon {$path}");
            }

            return false;
        }

        return $expired === false;
    }

    /**
     * get_cached_icon: the cached icon unless it is older than ICON_CACHE_TTL.
     */
    private function cachedIcon(string $path): ?string
    {
        if ($this->isExpired($path, $this->config->int('icon_cache_ttl')) ?? true) {
            return null;
        }
        $icon = @file_get_contents($this->file($path));

        return $icon === false ? null : $icon;
    }

    /**
     * file_is_expired: null when the file is missing or was modified in the future.
     */
    private function isExpired(string $path, int $ttl): ?bool
    {
        clearstatcache(true, $this->file($path));
        $modified = @filemtime($this->file($path));
        if ($modified === false || $modified > time()) {
            return null;
        }

        return $ttl > 0 && $ttl <= time() - $modified;
    }

    private function save(string $path, string $icon): void
    {
        $folder = $this->config->path('icon_cache_folder');
        if (! is_dir($folder)) {
            @mkdir($folder, 0777, true);
        }
        if (@file_put_contents($this->file($path), $icon) === false) {
            Log::warning("Unable to save icon: {$path}");
        }
    }

    private function file(string $path): string
    {
        return $this->config->path('icon_cache_folder').DIRECTORY_SEPARATOR.$path;
    }

    /**
     * std::str::from_utf8(..).unwrap_or_default().
     */
    private static function utf8OrEmpty(string $bytes): string
    {
        return mb_check_encoding($bytes, 'UTF-8') ? $bytes : '';
    }
}
