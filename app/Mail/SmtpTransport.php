<?php

namespace App\Mail;

use App\Config\Config;
use App\Http\ApiError;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\Transport\Smtp\Auth\AuthenticatorInterface;
use Symfony\Component\Mailer\Transport\Smtp\Auth\LoginAuthenticator;
use Symfony\Component\Mailer\Transport\Smtp\Auth\PlainAuthenticator;
use Symfony\Component\Mailer\Transport\Smtp\Auth\XOAuth2Authenticator;
use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Symfony\Component\Mime\Message;

/**
 * mail::smtp_transport, configured like lettre: SMTP_SECURITY off (no TLS
 * at all), starttls (required) or force_tls (implicit TLS), and the PLAIN
 * and LOGIN mechanisms unless SMTP_AUTH_MECHANISM names others.
 *
 * SMTP_TIMEOUT is how long one wait for the server may take; lettre's is the
 * same. Sending one mail, from connecting to quitting, may take
 * TOTAL_TIMEOUTS times as long (see DeadlineStream), so that a server which
 * answers a little at a time cannot hold the PHP worker.
 */
final readonly class SmtpTransport implements Transport
{
    /**
     * How many times SMTP_TIMEOUT the whole sending of a mail may take.
     */
    public const int TOTAL_TIMEOUTS = 4;

    public function __construct(
        private Config $config,
    ) {}

    public function send(Message $message, Envelope $envelope): void
    {
        try {
            $this->transport()->send($message, $envelope);
        } catch (TransportExceptionInterface $error) {
            $code = $error->getCode();
            $text = $error->getMessage();
            throw ApiError::message(match (true) {
                $code >= 400 && $code < 500 => "SMTP 4xx error: {$text}",
                // A failed login is the common case; upstream says so.
                $code === 535 => "SMTP 5xx error: {$text} - Authentication credentials invalid",
                $code >= 500 && $code < 600 => "SMTP 5xx error: {$text}",
                default => "SMTP error: {$text}",
            });
        }
    }

    private function transport(): EsmtpTransport
    {
        $host = $this->config->optionalString('smtp_host') ?? throw ApiError::message('SMTP error: no SMTP_HOST');
        $security = $this->config->string('smtp_security');

        $timeout = (float) max(1, $this->config->int('smtp_timeout'));
        $stream = new DeadlineStream($timeout, $timeout * self::TOTAL_TIMEOUTS);
        $transport = new EsmtpTransport($host, $this->config->int('smtp_port'), $security === 'force_tls', stream: $stream);
        if ($security === 'off') {
            $transport->setAutoTls(false);
        } elseif ($security === 'starttls') {
            $transport->setRequireTls(true);
        }

        $stream->setStreamOptions(['ssl' => [
            'verify_peer' => ! $this->config->bool('smtp_accept_invalid_certs'),
            'allow_self_signed' => $this->config->bool('smtp_accept_invalid_certs'),
            'verify_peer_name' => ! $this->config->bool('smtp_accept_invalid_hostnames'),
        ]]);

        $username = $this->config->optionalString('smtp_username');
        $password = $this->config->optionalString('smtp_password');
        if ($username !== null && $password !== null) {
            $transport->setUsername($username);
            $transport->setPassword($password);
        }

        $helo = $this->config->optionalString('helo_name');
        if ($helo !== null) {
            $transport->setLocalDomain($helo);
        }

        $transport->setAuthenticators($this->authenticators());

        return $transport;
    }

    /**
     * SMTP_AUTH_MECHANISM: a comma separated list of Plain, Login and
     * Xoauth2, quotes and case ignored; lettre's defaults otherwise.
     *
     * @return list<AuthenticatorInterface>
     */
    private function authenticators(): array
    {
        $available = ['plain' => new PlainAuthenticator, 'login' => new LoginAuthenticator, 'xoauth2' => new XOAuth2Authenticator];
        $mechanism = $this->config->optionalString('smtp_auth_mechanism');
        if ($mechanism === null) {
            return [$available['plain'], $available['login']];
        }

        $selected = [];
        foreach (explode(',', $mechanism) as $wanted) {
            $wanted = strtolower(trim($wanted, "\"' "));
            if (isset($available[$wanted])) {
                $selected[] = $available[$wanted];
            }
        }
        if ($selected === []) {
            logger()->warning("No valid SMTP Auth mechanism found for '{$mechanism}', using default values");

            return [$available['plain'], $available['login']];
        }

        return $selected;
    }
}
