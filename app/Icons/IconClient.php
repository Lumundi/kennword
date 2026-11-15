<?php

namespace App\Icons;

use App\Config\Config;
use App\Support\BlockedHost;
use App\Support\CookieJar;
use App\Support\HttpClient;
use App\Support\HttpRequestFailed;
use App\Support\HttpResponse;
use Uri\WhatWg\Url;

/**
 * The CLIENT of src/api/icons.rs: requests that look like Chrome's, with
 * a short-lived cookie jar and ICON_DOWNLOAD_TIMEOUT. Tests replace it in
 * the container.
 */
class IconClient
{
    private const array HEADERS = [
        'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language' => 'en-US,en;q=0.9',
        'Cache-Control' => 'no-cache',
        'Pragma' => 'no-cache',
        'Upgrade-Insecure-Requests' => '1',
        'Sec-Ch-Ua-Mobile' => '?0',
        'Sec-Ch-Ua-Platform' => 'Linux',
        'Sec-Ch-Ua' => '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
        'Sec-Fetch-Site' => 'none',
        'Sec-Fetch-Mode' => 'navigate',
        'Sec-Fetch-User' => '?1',
        'Sec-Fetch-Dest' => 'document',
    ];

    public function __construct(private readonly Config $config) {}

    /**
     * get_page_with_referer: the response to a GET of the URL, within
     * ICON_DOWNLOAD_TIMEOUT or the shorter time left of a download.
     *
     * @throws BlockedHost When the host is blocked, before or after resolving it
     * @throws HttpRequestFailed
     */
    public function get(string $url, string $referer = '', ?float $timeout = null): HttpResponse
    {
        // The resolver only sees names, so addresses in the URL are checked here.
        $parsed = Url::parse($url) ?? throw new HttpRequestFailed("Invalid URL: {$url}");
        if (! in_array($parsed->getScheme(), ['http', 'https'], true)) {
            throw new HttpRequestFailed("Invalid scheme: {$url}");
        }
        $host = $parsed->getAsciiHost();
        if ($host === null || $host === '') {
            throw new HttpRequestFailed("Invalid host: {$url}");
        }
        $reason = HttpClient::blockReason($host);
        if ($reason !== null) {
            throw new BlockedHost($reason);
        }

        $headers = $referer === '' ? self::HEADERS : [...self::HEADERS, 'Referer' => $referer];
        $cookies = CookieJar::load();
        try {
            $limit = (float) $this->config->int('icon_download_timeout');

            return HttpClient::get($parsed, $headers, $timeout === null ? $limit : min($limit, $timeout), $cookies);
        } finally {
            $cookies->save();
        }
    }
}
