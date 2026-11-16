<?php

namespace App\Mail;

use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\Transport\Smtp\Stream\AbstractStream;

/**
 * The socket of an SMTP session (Symfony's SocketStream) with a deadline for
 * all of it. SocketStream only times out when one read finds nothing for
 * SMTP_TIMEOUT, so a server that sends a byte every few seconds, or takes a
 * byte at a time, would hold a PHP worker for as long as it likes. Every
 * connect, handshake, read and write here stops at the deadline, and no wait
 * outlasts the idle timeout either.
 *
 * It offers what EsmtpTransport asks of its stream.
 */
final class DeadlineStream extends AbstractStream
{
    private string $host = 'localhost';

    private int $port = 25;

    private bool $tls = true;

    /**
     * @var array{ssl?: array<string, mixed>}
     */
    private array $streamContextOptions = [];

    private string $buffer = '';

    private string $debugTrail = '';

    private readonly float $deadline;

    /**
     * @param  float  $idle  Seconds to wait for the server at one time
     * @param  float  $total  Seconds the whole session may take, from now on
     */
    public function __construct(
        private readonly float $idle,
        float $total,
    ) {
        $this->deadline = microtime(true) + $total;
    }

    public function setHost(string $host): static
    {
        $this->host = $host;

        return $this;
    }

    public function getHost(): string
    {
        return $this->host;
    }

    public function setPort(int $port): static
    {
        $this->port = $port;

        return $this;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function disableTls(): static
    {
        $this->tls = false;

        return $this;
    }

    public function isTLS(): bool
    {
        return $this->tls;
    }

    /**
     * @param  array{ssl?: array<string, mixed>}  $options
     */
    public function setStreamOptions(array $options): static
    {
        $this->streamContextOptions = $options;

        return $this;
    }

    public function initialize(): void
    {
        $options = $this->streamContextOptions;
        $options['ssl']['crypto_method'] ??= STREAM_CRYPTO_METHOD_TLS_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT;
        $options['ssl']['peer_name'] ??= trim($this->host, '[]');

        $url = "tcp://{$this->host}:{$this->port}";
        set_error_handler(function (int $type, string $message) use ($url): never {
            throw new TransportException(sprintf('Connection could not be established with host "%s": ', $url).$message);
        });
        try {
            $stream = stream_socket_client($url, $code, $text, $this->remaining(), STREAM_CLIENT_CONNECT, stream_context_create($options));
        } finally {
            restore_error_handler();
        }
        if ($stream === false) {
            throw new TransportException(sprintf('Connection could not be established with host "%s": %s', $url, $text));
        }

        // Waits happen in stream_select(), against the deadline.
        stream_set_blocking($stream, false);
        $this->stream = $this->in = $this->out = $stream;
        $this->buffer = '';

        // Implicit TLS (SMTP_SECURITY=force_tls)
        if ($this->tls && ! $this->startTLS()) {
            throw new TransportException(sprintf('Connection could not be established with host "%s": TLS handshake failed', $url));
        }
    }

    public function startTLS(): bool
    {
        $stream = $this->stream;
        if ($stream === null) {
            return false;
        }

        set_error_handler(static function (int $type, string $message): never {
            throw new TransportException('Unable to connect with STARTTLS: '.$message);
        });
        try {
            // A handshake on a non-blocking stream answers 0 until it has what it needs.
            while (($result = stream_socket_enable_crypto($stream, true)) === 0) {
                $this->wait($stream, false);
            }

            return $result === true;
        } finally {
            restore_error_handler();
        }
    }

    public function write(string $bytes, bool $debug = true): void
    {
        $stream = $this->stream;
        if ($stream === null) {
            throw new TransportException('Unable to write bytes on the wire.');
        }
        if ($debug) {
            $this->logSent($bytes);
        }

        while ($bytes !== '') {
            $written = @fwrite($stream, $bytes);
            if ($written === false) {
                throw new TransportException('Unable to write bytes on the wire.');
            }
            if ($written === 0) {
                $this->wait($stream, true);

                continue;
            }
            $bytes = substr($bytes, $written);
        }
    }

    public function flush(): void
    {
        // Nothing is buffered: fwrite() on a socket sends at once.
    }

    public function readLine(): string
    {
        $stream = $this->stream;
        if ($stream === null) {
            return '';
        }

        while (($end = strpos($this->buffer, "\n")) === false) {
            $chunk = @fread($stream, 8192);
            if ($chunk === false || ($chunk === '' && feof($stream))) {
                throw new TransportException(sprintf('Connection to "%s" has been closed unexpectedly.', $this->getReadConnectionDescription()));
            }
            if ($chunk === '') {
                $this->wait($stream, false);

                continue;
            }
            $this->buffer .= $chunk;
        }

        $line = substr($this->buffer, 0, $end + 1);
        $this->buffer = substr($this->buffer, $end + 1);
        $this->logReceived($line);

        return $line;
    }

    public function hasPendingData(): bool
    {
        if ($this->buffer !== '') {
            return true;
        }

        return parent::hasPendingData();
    }

    public function terminate(): void
    {
        if ($this->stream !== null) {
            fclose($this->stream);
        }
        $this->buffer = '';

        parent::terminate();
    }

    protected function getReadConnectionDescription(): string
    {
        return "{$this->host}:{$this->port}";
    }

    /**
     * Seconds left before the deadline.
     *
     * @throws TransportException When there are none
     */
    private function remaining(): float
    {
        $remaining = $this->deadline - microtime(true);
        if ($remaining <= 0) {
            throw new TransportException(sprintf('Connection to "%s" timed out.', $this->getReadConnectionDescription()));
        }

        return $remaining;
    }

    /**
     * Wait until the stream can be read or written, for no longer than the
     * idle timeout or the deadline.
     *
     * @param  resource  $stream
     *
     * @throws TransportException
     */
    private function wait($stream, bool $forWriting): void
    {
        $seconds = min($this->idle, $this->remaining());
        $read = $forWriting ? null : [$stream];
        $write = $forWriting ? [$stream] : null;
        $except = null;
        $ready = @stream_select($read, $write, $except, (int) $seconds, (int) (($seconds - (int) $seconds) * 1_000_000));
        if ($ready === 0) {
            throw new TransportException(sprintf('Connection to "%s" timed out.', $this->getReadConnectionDescription()));
        }
    }

    private function logSent(string $bytes): void
    {
        $this->debugTrail .= sprintf('[%s] > %s'."\n", (new \DateTimeImmutable)->format('Y-m-d\TH:i:s.up'), trim($bytes));
    }

    private function logReceived(string $line): void
    {
        $this->debugTrail .= sprintf('[%s] < %s', (new \DateTimeImmutable)->format('Y-m-d\TH:i:s.up'), $line);
    }

    public function getDebug(): string
    {
        $debug = $this->debugTrail;
        $this->debugTrail = '';

        return $debug;
    }
}
