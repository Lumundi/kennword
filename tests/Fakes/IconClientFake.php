<?php

namespace Tests\Fakes;

use App\Icons\IconClient;
use App\Support\BlockedHost;
use App\Support\HttpClient;
use App\Support\HttpRequestFailed;
use App\Support\HttpResponse;
use Uri\WhatWg\Url;

/**
 * Websites for the icon service: answers by URL, failures for the rest.
 * Addresses are still checked like IconClient does, before a site answers.
 */
final class IconClientFake extends IconClient
{
    /**
     * @var array<string, array{int, string, string}|HttpRequestFailed> By URL: the status, the body and the URL after redirects
     */
    private array $sites = [];

    /**
     * @var list<array{string, string}> The URLs asked for, with their Referer
     */
    public array $requests = [];

    /**
     * Microseconds each request takes, like a slow site.
     */
    public int $delay = 0;

    public function answer(string $url, string $body, int $status = 200, ?string $finalUrl = null): self
    {
        $this->sites[$url] = [$status, $body, $finalUrl ?? $url];

        return $this;
    }

    public function fail(string $url, HttpRequestFailed $failure): self
    {
        $this->sites[$url] = $failure;

        return $this;
    }

    public function get(string $url, string $referer = '', ?float $timeout = null): HttpResponse
    {
        $this->requests[] = [$url, $referer];
        usleep($this->delay);

        $parsed = Url::parse($url) ?? throw new HttpRequestFailed("Invalid URL: {$url}");
        $reason = HttpClient::blockReason((string) $parsed->getAsciiHost());
        if ($reason !== null) {
            throw new BlockedHost($reason);
        }

        $site = $this->sites[$url] ?? new HttpRequestFailed("Connection refused: {$url}");
        if ($site instanceof HttpRequestFailed) {
            throw $site;
        }
        [$status, $body, $finalUrl] = $site;
        if ($status >= 400) {
            throw new HttpRequestFailed("HTTP status {$status} for URL ({$url})");
        }

        $stream = fopen('php://memory', 'w+b');
        if ($stream === false) {
            throw new HttpRequestFailed('No memory stream');
        }
        fwrite($stream, $body);
        rewind($stream);

        return new HttpResponse(Url::parse($finalUrl) ?? $parsed, $status, [], $stream, microtime(true) + 10);
    }
}
