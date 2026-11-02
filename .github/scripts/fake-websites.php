<?php

/**
 * Websites with icons for tests/Differential/IconsTest: the icon service
 * fetches https://<host>/ and http://<host>/ itself, so these listen on
 * ports 80 and 443 and answer by the Host header. Each connection gets a
 * process of its own, so that slow sites do not hold up the others.
 *
 * Usage: php fake-websites.php <certificate> <key> <state dir> [address]
 *        php fake-websites.php --names    (the host names, for /etc/hosts and the certificate)
 *
 * The certificate covers every name except httponly.icons.localhost, whose
 * HTTPS therefore fails. Tests switch sites in the state dir: a file named
 * after the host holds its variant.
 */
const SITES = [
    'icons.localhost', 'links.icons.localhost', 'favicon.icons.localhost', 'redirect.icons.localhost', 'fourhops.icons.localhost',
    'fivehops.icons.localhost', 'httponly.icons.localhost', 'missing.icons.localhost', 'broken.icons.localhost',
    'allbroken.icons.localhost', 'oversized.icons.localhost', 'bigpage.icons.localhost', 'svg.icons.localhost',
    'brokensvg.icons.localhost', 'datauri.icons.localhost', 'tricky.icons.localhost', 'entities.icons.localhost', 'dupes.icons.localhost',
    'quirk.icons.localhost', 'basename.icons.localhost', 'baseattr.icons.localhost', 'gzip.icons.localhost',
    'chunked.icons.localhost', 'cookie.icons.localhost', 'slowicon.icons.localhost', 'gif.icons.localhost', 'jpeg.icons.localhost',
    'webp.icons.localhost', 'bmp.icons.localhost', 'linkblocked.icons.localhost', 'blocked.icons.localhost',
    'invalidlink.icons.localhost', 'negative.localhost', 'cached.icons.localhost', 'wwwonly.localhost', 'www.wwwonly.localhost',
];

if (($argv[1] ?? null) === '--names') {
    echo implode("\n", SITES), "\n";
    exit(0);
}
[, $certificate, $key, $state, $address] = $argv + [null, null, null, null, '127.0.0.1'];
if (! is_string($certificate) || ! is_string($key) || ! is_string($state)) {
    fwrite(STDERR, "Usage: php fake-websites.php <certificate> <key> <state dir> [address]\n");
    exit(2);
}
if (! is_dir($state)) {
    mkdir($state, 0777, true);
}

$servers = [];
foreach (['http' => 80, 'https' => 443] as $scheme => $port) {
    $server = stream_socket_server("tcp://{$address}:{$port}", $errno, $error);
    if ($server === false) {
        fwrite(STDERR, "Cannot listen on {$address}:{$port}: {$error}\n");
        exit(1);
    }
    $servers[$scheme] = $server;
}
$tls = stream_context_create(['ssl' => ['local_cert' => $certificate, 'local_pk' => $key, 'verify_peer' => false]]);
$fork = function_exists('pcntl_fork');
if ($fork) {
    pcntl_signal(SIGCHLD, SIG_IGN);
}

while (true) {
    $read = array_values($servers);
    $write = $except = null;
    if (@stream_select($read, $write, $except, null) === false) {
        continue;
    }
    foreach ($read as $server) {
        $client = @stream_socket_accept($server, 0);
        if ($client === false) {
            continue;
        }
        $scheme = $server === $servers['https'] ? 'https' : 'http';
        $pid = $fork ? pcntl_fork() : -1;
        if ($pid > 0) {
            fclose($client);

            continue;
        }
        serve($client, $scheme, $tls, $state);
        if ($pid === 0) {
            exit(0);
        }
    }
}

/**
 * @param  resource  $client
 * @param  resource  $tls
 */
function serve($client, string $scheme, $tls, string $state): void
{
    stream_set_timeout($client, 10);
    if ($scheme === 'https') {
        stream_context_set_option($client, 'ssl', 'local_cert', stream_context_get_options($tls)['ssl']['local_cert']);
        stream_context_set_option($client, 'ssl', 'local_pk', stream_context_get_options($tls)['ssl']['local_pk']);
        if (@stream_socket_enable_crypto($client, true, STREAM_CRYPTO_METHOD_TLS_SERVER) !== true) {
            fclose($client);

            return;
        }
    }

    $head = '';
    while (! str_contains($head, "\r\n\r\n") && ($line = fgets($client)) !== false) {
        $head .= $line;
    }
    $lines = explode("\r\n", trim($head));
    [, $target] = explode(' ', array_shift($lines) ?? '') + ['', ''];
    $headers = [];
    foreach ($lines as $line) {
        [$name, $value] = explode(':', $line, 2) + ['', ''];
        $headers[strtolower(trim($name))] = trim($value);
    }
    $host = strtolower((string) preg_replace('/:\d+$/', '', $headers['host'] ?? ''));

    $response = respond($scheme, $host, $target, $headers, $state) + ['headers' => [], 'body' => [''], 'chunked' => false];
    $body = $response['body'];
    $gzip = ($response['gzip'] ?? false) && str_contains($headers['accept-encoding'] ?? '', 'gzip');
    if ($gzip) {
        $body = [(string) gzencode(implode('', array_filter($body, 'is_string')))];
        $response['headers']['Content-Encoding'] = 'gzip';
    }

    $reasons = [200 => 'OK', 301 => 'Moved Permanently', 302 => 'Found', 307 => 'Temporary Redirect', 404 => 'Not Found', 500 => 'Internal Server Error'];
    $out = "HTTP/1.1 {$response['status']} ".($reasons[$response['status']] ?? 'Unknown')."\r\nConnection: close\r\n";
    foreach ($response['headers'] as $name => $value) {
        foreach ((array) $value as $one) {
            $out .= "{$name}: {$one}\r\n";
        }
    }
    $length = array_sum(array_map(static fn (mixed $part): int => is_string($part) ? strlen($part) : 0, $body));
    $out .= $response['chunked'] ? "Transfer-Encoding: chunked\r\n" : "Content-Length: {$length}\r\n";
    fwrite($client, "{$out}\r\n");

    // Parts of the body, with pauses (in seconds) in between.
    foreach ($body as $part) {
        if (is_string($part)) {
            for ($offset = 0; $offset < strlen($part); $offset += 65536) {
                $chunk = substr($part, $offset, 65536);
                if (@fwrite($client, $response['chunked'] ? dechex(strlen($chunk))."\r\n{$chunk}\r\n" : $chunk) === false) {
                    break 2;
                }
            }
        } else {
            fflush($client);
            usleep((int) ($part * 1_000_000));
        }
    }
    if ($response['chunked']) {
        @fwrite($client, "0\r\n\r\n");
    }
    @fclose($client);
}

/**
 * An image of the type whose bytes tell which one it is.
 */
function image(string $type, string $name): string
{
    return match ($type) {
        'png' => "\x89PNG\r\n\x1A\n",
        'ico' => "\0\0\1\0\1\0",
        'gif' => 'GIF89a',
        'jpeg' => "\xFF\xD8\xFF\xE0",
        'webp' => 'RIFF0000WEBPVP8 ',
        'bmp' => "BM\x10\0\0\0\0\0\0\0",
    }.str_pad(" {$name}", 64, '.');
}

function page(string $head): string
{
    return "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>Icons</title>\n{$head}\n</head><body><p>Hello</p></body></html>\n";
}

/**
 * @param  array<string, string>  $headers
 * @return array{status: int, headers?: array<string, string|list<string>>, body?: list<string|float>, chunked?: bool, gzip?: bool}
 */
function respond(string $scheme, string $host, string $target, array $headers, string $state): array
{
    $path = (string) parse_url($target, PHP_URL_PATH);
    $ok = static fn (string $body, string $type = 'text/html; charset=utf-8'): array => ['status' => 200, 'headers' => ['Content-Type' => $type], 'body' => [$body]];
    $notFound = ['status' => 404, 'headers' => ['Content-Type' => 'text/html'], 'body' => ['<h1>Not found</h1>']];
    $redirect = static fn (string $location, int $status = 302): array => ['status' => $status, 'headers' => ['Location' => $location], 'body' => ['']];
    $variant = @file_get_contents("{$state}/{$host}") ?: '';

    // A favicon.ico wherever there is no better answer.
    if ($path === '/favicon.ico' && ! in_array($host, ['allbroken.icons.localhost', 'negative.localhost', 'cached.icons.localhost'], true)) {
        return $ok(image('ico', "{$scheme}://{$host}/favicon.ico"), 'image/x-icon');
    }

    return match ($host) {
        // The domain without subdomains, for those that fail.
        'icons.localhost', '127.0.0.1' => match ($path) {
            '/' => $ok(page('<link rel="icon" href="/base.png">')),
            '/base.png' => $ok(image('png', "{$host}/base.png"), 'image/png'),
            default => $notFound,
        },
        'links.icons.localhost' => $path === '/' ? $ok(page(implode("\n", [
            '<link rel="icon" href="/16.png" sizes="16x16">',
            '<link rel="icon" type="image/png" href="/32.png" sizes="32x32">',
            '<link rel="apple-touch-icon" href="/apple.png" sizes="180x180">',
            '<link rel="mask-icon" href="/mask.svg" color="#000">',
            '<link rel="icon" href="/any.svg" sizes="any">',
        ]))) : $ok(image('png', $path), 'image/png'),
        'favicon.icons.localhost' => $path === '/' ? $ok(page('')) : $notFound,
        // Redirects for the page and the icon; the icon is relative to the last URL.
        'redirect.icons.localhost' => match ($path) {
            '/' => $redirect('/start/', 301),
            '/start/' => $redirect('https://redirect.icons.localhost/landing/page.html'),
            '/landing/page.html' => $ok(page('<link rel="icon" href="icon.png">')),
            '/landing/icon.png' => $redirect('/real/icon.png', 307),
            '/real/icon.png' => $ok(image('png', 'redirected'), 'image/png'),
            default => $notFound,
        },
        // Four redirects are followed, the fifth is an error.
        'fourhops.icons.localhost', 'fivehops.icons.localhost' => match (true) {
            $path === '/' => $redirect('/1'),
            preg_match('#^/(\d)$#', $path, $hop) === 1 && (int) $hop[1] < ($host === 'fourhops.icons.localhost' ? 4 : 5) => $redirect('/'.((int) $hop[1] + 1)),
            preg_match('#^/\d$#', $path) === 1 => $ok(page('<link rel="icon" href="/hops.png">')),
            $path === '/hops.png' => $ok(image('png', $host), 'image/png'),
            default => $notFound,
        },
        'httponly.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" href="/http.gif">')),
            '/http.gif' => $ok(image('gif', "{$scheme} only"), 'image/gif'),
            default => $notFound,
        },
        // Images that are none, missing or cut short, before one that is fine.
        'broken.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" href="/a.png"><link rel="icon" href="/b.png"><link rel="icon" href="/c.png"><link rel="icon" href="/d.png">')),
            '/a.png' => $ok('<html>not an image</html>', 'image/png'),
            '/c.png' => $ok("\x89PNG\r\n", 'image/png'),
            '/d.png' => $ok(image('png', 'fine'), 'image/png'),
            default => $notFound,
        },
        'allbroken.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" href="/a.png">')),
            '/a.png' => $ok('<html>not an image</html>', 'image/png'),
            default => $notFound,
        },
        // Five MB of an icon arrive, then a pause, then the rest.
        'oversized.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" href="/big.png">')),
            '/big.png' => ['status' => 200, 'headers' => ['Content-Type' => 'image/png'],
                'body' => [image('png', 'big').str_repeat('x', 5120 * 1024 - 72), 1.0, str_repeat('y', 1024 * 1024)]],
            default => $notFound,
        },
        // Only the first 384 KB of a page count.
        'bigpage.icons.localhost' => match ($path) {
            '/' => ['status' => 200, 'headers' => ['Content-Type' => 'text/html'], 'body' => [
                str_pad('<!DOCTYPE html><html><head><title>Big</title><meta name="filler" content="', 384 * 1024, 'z'), 1.0,
                str_repeat('z', 16 * 1024).'"><link rel="icon" href="/late.png"></head></html>',
            ]],
            '/late.png' => $ok(image('png', 'late'), 'image/png'),
            default => $notFound,
        },
        'svg.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" type="image/svg+xml" href="/icon.svg">')),
            '/icon.svg' => $ok(svg(), 'image/svg+xml'),
            default => $notFound,
        },
        'brokensvg.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" href="/icon.svg">')),
            '/icon.svg' => $ok('<svg xmlns="http://www.w3.org/2000/svg"><path d="M0"></svg>', 'image/svg+xml'),
            default => $notFound,
        },
        'datauri.icons.localhost' => $path === '/' ? $ok(page(
            '<link rel="icon" sizes="32x32" href="data:image/png;base64,'.base64_encode("\x89PNG\r\n\x1A\nsmall").'">'
            .'<link rel="icon" sizes="64x64" href="data:image/gif;base64,'.base64_encode(image('gif', 'inline')).'">'
            .'<link rel="icon" sizes="24x24" href="data:text/plain,'.rawurlencode(image('png', 'text')).'">',
        )) : $notFound,
        // Every link but the right one would win, if it were taken; images name their URL.
        'tricky.icons.localhost', 'entities.icons.localhost', 'dupes.icons.localhost', 'quirk.icons.localhost', 'basename.icons.localhost',
        'baseattr.icons.localhost' => $path === '/'
            ? $ok(tricky($host))
            : $ok(image('png', $target), 'image/png'),
        'gzip.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" href="/zipped.png">')) + ['gzip' => true],
            '/zipped.png' => $ok(image('png', 'zipped'), 'image/png') + ['gzip' => true],
            default => $notFound,
        },
        'chunked.icons.localhost' => match ($path) {
            '/' => ['status' => 200, 'headers' => ['Content-Type' => 'text/html'], 'chunked' => true,
                'body' => [page('<link rel="icon" href="/chunked.png">')]],
            '/chunked.png' => ['status' => 200, 'headers' => ['Content-Type' => 'image/png'], 'chunked' => true, 'body' => [image('png', 'chunked')]],
            default => $notFound,
        },
        // Lets in only clients that keep its cookie.
        'cookie.icons.localhost' => match (true) {
            ! str_contains($headers['cookie'] ?? '', 'visited=yes') => ['status' => 302,
                'headers' => ['Location' => $path, 'Set-Cookie' => ['visited=yes; Path=/; Max-Age=31536000', 'other=1; Domain=icons.localhost; Path=/x']], 'body' => ['']],
            $path === '/' => $ok(page('<link rel="icon" href="/cookie.png">')),
            $path === '/cookie.png' => $ok(image('png', 'cookie'), 'image/png'),
            default => $notFound,
        },
        // An icon that takes longer than ICON_DOWNLOAD_TIMEOUT.
        'slowicon.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" href="/slow.png">')),
            '/slow.png' => ['status' => 200, 'headers' => ['Content-Type' => 'image/png'], 'body' => [6.0, image('png', 'slow')]],
            default => $notFound,
        },
        'gif.icons.localhost', 'jpeg.icons.localhost', 'webp.icons.localhost', 'bmp.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="shortcut icon" href="/icon">')),
            '/icon' => $ok(image(explode('.', $host)[0], $host), 'application/octet-stream'),
            default => $notFound,
        },
        // Links to blocked or invalid hosts end the search.
        'linkblocked.icons.localhost', 'invalidlink.icons.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" sizes="32x32" href="https://'.($host === 'linkblocked.icons.localhost' ? 'blocked' : 'bad_name')
                .'.icons.localhost/a.png"><link rel="icon" href="/b.png">')),
            '/b.png' => $ok(image('png', 'after the blocked one'), 'image/png'),
            default => $notFound,
        },
        'blocked.icons.localhost' => $ok(image('png', 'blocked'), 'image/png'),
        // Switched by the tests: nothing at first, then an icon.
        'negative.localhost', 'cached.icons.localhost' => match (true) {
            $variant === '' && $host === 'negative.localhost' => $notFound,
            $path === '/' => $ok(page('<link rel="icon" href="/icon.png">')),
            $path === '/icon.png' => $ok(image('png', "{$host} {$variant}"), 'image/png'),
            default => $notFound,
        },
        'www.wwwonly.localhost' => match ($path) {
            '/' => $ok(page('<link rel="icon" href="/www.png">')),
            '/www.png' => $ok(image('png', 'www'), 'image/png'),
            default => $notFound,
        },
        'wwwonly.localhost', 'missing.icons.localhost' => ['status' => 500, 'body' => ['Down']],
        default => $notFound,
    };
}

/**
 * Pages with what a tokenizer may trip over, in CRLF lines.
 */
function tricky(string $host): string
{
    return implode("\r\n", match ($host) {
        'tricky.icons.localhost' => [
            '<!DOCTYPE html>',
            '<HTML><HEAD><TITLE>Tricky <link rel="icon" href="/title.png" sizes="32x32"></TITLE>',
            '<script>document.write("<link rel=\'icon\' href=\'/script.png\' sizes=\'32x32\'>");</script>',
            '<script><!--<script>"</script><link rel=icon href=/double-escaped.png sizes=32x32></script>--></script>',
            '<!-- <link rel="icon" href="/comment.png" sizes="32x32"> -->',
            '<noscript><link rel="icon" href="/noscript.png" sizes="32x32"></noscript>',
            '<textarea><link rel="icon" href="/textarea.png" sizes="32x32"></textarea>',
            '<![CDATA[<link rel="icon" href="/cdata.png" sizes="32x32">]]>',
            '<link rel="ICON" href="/upper-rel.png" sizes="32x32"><link rel="mask-icon" href="/mask.png" sizes="32x32">',
            '<link rel=icon href=/right.png sizes=64x64>',
            '</head><link rel="icon" href="/after-head.png" sizes="32x32">',
        ],
        'entities.icons.localhost' => [
            '<base href="/assets/"><base href="icons/">',
            '<LINK REL="shortcut icon" HREF="a.png?x=1&amp;y=2&copy=3&copy;&#x41;&#0;&notit;&#128;" SIZES="32X32">',
        ],
        'dupes.icons.localhost' => ['<link rel=icon href=/first.png href=/second.png sizes=32x32>'],
        // The base leaves at its first href; its second waits and goes to the link.
        'quirk.icons.localhost' => ['<base href="/a/" href=/b/>', '<link rel=icon href=x.png sizes=32x32>'],
        // Since html5gum 0.9.0 the end of an attribute name comes before the base leaves:
        // its rel stays with it, or the name after it waits for the link.
        'basename.icons.localhost' => ['<base href=/ rel><link rel=icon href=/b.png sizes=32x32>'],
        'baseattr.icons.localhost' => ['<base href=/ x rel><link rel=icon href=/b.png sizes=32x32>'],
    });
}

function svg(): string
{
    return implode("\n", [
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
        '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">',
        '<!-- Generator: a test -->',
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" viewBox="0 0 32 32" onload="alert(1)" aria-label=" Icon ">',
        "\t<script>alert(1)</script>",
        "\t<style><![CDATA[ .a { fill: url(https://evil.example/x.svg#g) } @import url(x.css); ]]></style>",
        "\t<defs><linearGradient id=\"g\"><stop offset=\"0\" stop-color=\"#fff\"/><stop offset=\"1\" stop-color=\"#000\"/></linearGradient></defs>",
        "\t<a href=\"https://example.com/\"><use xlink:href=\"#g\" href=\"https://evil.example/#b\"/></a>",
        "\t<image href=\"data:image/png;base64,AAAA\" x=\"1\"/><image href=\"data:text/html,x\"/>",
        "\t<g fill=\"url(#g)\" xml:space=\"preserve\"><title>T &amp; &lt;&gt; \"q\"</title></g>",
        "\t<foreignObject><div xmlns=\"http://www.w3.org/1999/xhtml\">Hi</div></foreignObject>",
        "\t<path d=\"M0 0\n\t\tL32 32\" class=\"a\" data-x=\"1\"/>",
        '</svg>',
    ]);
}
