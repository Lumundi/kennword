<?php

namespace Tests\Feature\Mail;

use App\Config\Config;
use App\Http\ApiError;
use App\Mail\SmtpTransport;
use RuntimeException;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Tests\Attributes\Parity;
use Tests\TestCase;

/**
 * mail::smtp_transport against SMTP servers of the tests: the sink of the
 * differential tests, and servers that never finish.
 */
#[Parity('config:SMTP_TIMEOUT')]
class SmtpTransportTest extends TestCase
{
    /**
     * @var list<resource>
     */
    private array $servers = [];

    private string $folder = '';

    protected function vaultwardenEnvironment(): array
    {
        return ['SMTP_HOST' => '127.0.0.1', 'SMTP_SECURITY' => 'off', 'SMTP_FROM' => 'vault@example.com', 'SMTP_TIMEOUT' => '1'];
    }

    protected function tearDown(): void
    {
        foreach ($this->servers as $process) {
            proc_terminate($process);
            proc_close($process);
        }
        if ($this->folder !== '') {
            exec('rm -rf '.escapeshellarg($this->folder));
        }
        parent::tearDown();
    }

    public function test_a_mail_reaches_the_server(): void
    {
        $this->folder = sys_get_temp_dir().'/vw-smtp-'.bin2hex(random_bytes(6));
        $port = $this->start(dirname(__DIR__, 3).'/.github/scripts/smtp-sink.php', $this->folder);
        $this->changeVaultwardenEnvironment(['SMTP_PORT' => (string) $port]);

        $this->transport()->send($this->mail(), new Envelope(new Address('vault@example.com'), [new Address('kim@example.com')]));

        $received = glob("{$this->folder}/*.eml");
        $this->assertCount(1, $received === false ? [] : $received);
        $this->assertStringContainsString('Subject: Hello', (string) file_get_contents($received[0] ?? ''));
    }

    public function test_a_server_that_says_nothing_is_given_up_on(): void
    {
        $port = $this->start(dirname(__DIR__, 3).'/.github/scripts/trickle-smtp.php', 'silent');
        $this->changeVaultwardenEnvironment(['SMTP_PORT' => (string) $port]);

        $took = $this->failingSend();

        $this->assertLessThan(3, $took, 'One wait for the server may take SMTP_TIMEOUT.');
    }

    /**
     * A server that sends a byte every half second never lets a single read run out of time.
     * The whole mail may take four times SMTP_TIMEOUT all the same.
     */
    public function test_a_server_that_trickles_cannot_hold_the_worker(): void
    {
        $port = $this->start(dirname(__DIR__, 3).'/.github/scripts/trickle-smtp.php', '0.5');
        $this->changeVaultwardenEnvironment(['SMTP_PORT' => (string) $port, 'SMTP_TIMEOUT' => '1']);

        $took = $this->failingSend();

        $this->assertGreaterThan(3, $took, 'Not before the deadline.');
        $this->assertLessThan(6, $took, 'The deadline is four times SMTP_TIMEOUT.');
    }

    /**
     * The seconds a send takes to fail with a timeout.
     */
    private function failingSend(): float
    {
        $start = microtime(true);
        try {
            $this->transport()->send($this->mail(), new Envelope(new Address('vault@example.com'), [new Address('kim@example.com')]));
            $this->fail('The mail cannot have been sent.');
        } catch (ApiError $error) {
            $this->assertStringContainsString('timed out', $error->displayText());
        }

        return microtime(true) - $start;
    }

    private function transport(): SmtpTransport
    {
        return new SmtpTransport($this->app->make(Config::class));
    }

    private function mail(): Email
    {
        return (new Email)->from('vault@example.com')->to('kim@example.com')->subject('Hello')->text('Hi');
    }

    /**
     * Start a script that listens on a free port; returns the port.
     */
    private function start(string $script, string $argument): int
    {
        $probe = stream_socket_server('tcp://127.0.0.1:0');
        $this->assertNotFalse($probe);
        $address = (string) stream_socket_get_name($probe, false);
        fclose($probe);
        $port = (int) substr($address, strrpos($address, ':') + 1);

        $process = proc_open([PHP_BINARY, $script, (string) $port, $argument], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        if ($process === false) {
            throw new RuntimeException('Cannot start the server.');
        }
        $this->servers[] = $process;

        for ($attempt = 0; $attempt < 50; $attempt++) {
            $client = @stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $error, 1);
            if ($client !== false) {
                fclose($client);

                return $port;
            }
            usleep(100_000);
        }

        throw new RuntimeException('The server did not start.');
    }
}
