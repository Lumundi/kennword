<?php

namespace App\Http;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Rocket's NamedFile: the bytes, streamed, with the content type Rocket knows
 * for the file's extension, or without a Content-Type (see EmptyResponse for
 * why it is removed here).
 */
final class FileResponse extends StreamedResponse
{
    /**
     * Bytes read and sent at a time.
     */
    public const int CHUNK_SIZE = 1024 * 1024;

    public function __construct(string $path, private readonly ?string $contentType = null)
    {
        parent::__construct(static function () use ($path): void {
            $handle = fopen($path, 'rb');
            if ($handle === false) {
                return;
            }
            try {
                self::pass($handle);
            } finally {
                fclose($handle);
            }
        }, 200, ['Content-Length' => (string) filesize($path)]);
    }

    /**
     * Sends the file chunk by chunk. fpassthru() hands the whole file to PHP's
     * output layer at once, and an output buffer (output_buffering, on in
     * php.ini-production) then holds all of it, so a file larger than
     * memory_limit could not be downloaded.
     *
     * @param  resource  $handle
     */
    private static function pass($handle): void
    {
        while (! feof($handle)) {
            $chunk = fread($handle, self::CHUNK_SIZE);
            if ($chunk === false || $chunk === '') {
                return;
            }
            echo $chunk;
            if (ob_get_level() > 0) {
                ob_flush();
            }
            flush();
        }
    }

    public function prepare(Request $request): static
    {
        parent::prepare($request);
        if ($this->contentType === null) {
            $this->headers->remove('Content-Type');
        } else {
            $this->headers->set('Content-Type', $this->contentType);
        }

        return $this;
    }

    /**
     * PHP would add its default charset to a text type without one, like text/javascript.
     */
    public function sendHeaders(?int $statusCode = null): static
    {
        $charset = (string) ini_get('default_charset');
        ini_set('default_charset', '');
        try {
            return parent::sendHeaders($statusCode);
        } finally {
            ini_set('default_charset', $charset);
        }
    }
}
