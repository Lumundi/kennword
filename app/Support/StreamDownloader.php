<?php

namespace App\Support;

use RuntimeException;

/**
 * Downloads with PHP's HTTP stream wrapper, straight into the file. Redirects
 * are followed here rather than by the wrapper, which would send the
 * Authorization header on to the storage a registry redirects to.
 */
final class StreamDownloader implements Downloader
{
    private const int MAX_REDIRECTS = 5;

    public function download(string $url, array $headers, string $file): int
    {
        if (! filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOL)) {
            throw new RuntimeException('PHP cannot download files: allow_url_fopen is off.');
        }

        for ($redirect = 0; $redirect <= self::MAX_REDIRECTS; $redirect++) {
            $lines = [];
            foreach (['User-Agent' => 'Kennword', ...$headers] as $name => $value) {
                $lines[] = "{$name}: {$value}";
            }
            $context = stream_context_create(['http' => [
                'header' => $lines,
                'timeout' => 60,
                'follow_location' => 0,
                'ignore_errors' => true,
                'protocol_version' => 1.1,
            ]]);

            $error = null;
            set_error_handler(static function (int $level, string $message) use (&$error): bool {
                $error = $message;

                return true;
            });
            try {
                $input = fopen($url, 'rb', false, $context);
            } finally {
                restore_error_handler();
            }
            if ($input === false) {
                throw new RuntimeException("No response from {$url}: ".($error ?? 'unknown error'));
            }

            try {
                [$status, $location] = self::statusAndLocation(stream_get_meta_data($input)['wrapper_data'] ?? []);
                if ($status >= 300 && $status < 400 && $location !== null) {
                    $next = self::resolve($url, $location);
                    if (parse_url($next, PHP_URL_HOST) !== parse_url($url, PHP_URL_HOST)) {
                        unset($headers['Authorization']);
                    }
                    $url = $next;

                    continue;
                }

                $output = @fopen($file, 'wb');
                if ($output === false) {
                    throw new RuntimeException("Cannot write {$file}.");
                }
                try {
                    $copied = stream_copy_to_stream($input, $output);
                } finally {
                    fclose($output);
                }
                if ($copied === false || stream_get_meta_data($input)['timed_out']) {
                    throw new RuntimeException("The download from {$url} broke off.");
                }

                return $status;
            } finally {
                fclose($input);
            }
        }

        throw new RuntimeException("Too many redirects from {$url}.");
    }

    /**
     * @param  mixed  $headers  The wrapper data: the header lines of each response
     * @return array{int, ?string}
     */
    private static function statusAndLocation(mixed $headers): array
    {
        $status = 0;
        $location = null;
        foreach (is_array($headers) ? $headers : [] as $header) {
            if (! is_string($header)) {
                continue;
            }
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $match) === 1) {
                $status = (int) $match[1];
                $location = null;
            } elseif (preg_match('/^location:\s*(\S+)/i', $header, $match) === 1) {
                $location = $match[1];
            }
        }

        return [$status, $location];
    }

    private static function resolve(string $url, string $location): string
    {
        if (preg_match('#^https?://#i', $location) === 1) {
            return $location;
        }
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $host = parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT);

        return "{$scheme}://{$host}".($port !== null ? ":{$port}" : '').'/'.ltrim($location, '/');
    }
}
