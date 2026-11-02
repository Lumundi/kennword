<?php

namespace Tests\Differential;

use GuzzleHttp\Client;
use PHPUnit\Framework\TestCase;

/**
 * Sends the same request to Vaultwarden (VW_REFERENCE_URL) and to this
 * implementation (VW_SUBJECT_URL) and compares what comes back: status,
 * the headers below and the body, after replacing values that differ by
 * nature (timestamps, UUIDs, tokens, the version). Without both URLs the
 * tests are skipped; .github/scripts/differential.sh starts both servers.
 */
abstract class DifferentialTestCase extends TestCase
{
    /**
     * Headers that must be equal. Cache-Control is compared as a set of
     * directives, because Symfony adds "private" and reorders them.
     */
    private const array HEADERS = [
        'content-type',
        'content-security-policy',
        'permissions-policy',
        'referrer-policy',
        'x-content-type-options',
        'x-frame-options',
        'x-robots-tag',
        'x-xss-protection',
        'cross-origin-resource-policy',
        'access-control-allow-origin',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-allow-credentials',
        'location',
    ];

    /**
     * Pattern => placeholder, applied to every string of a response.
     */
    private const array PLACEHOLDERS = [
        '/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z/' => '<date>',
        '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/' => '<uuid>',
        '/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/' => '<jwt>',
        // The reference is built from git, so its version carries the commit.
        '/^1\.37\.5(-[0-9a-f]{8})?$/' => '<version>',
        // Attachment ids and Send file ids.
        '/\b[0-9a-f]{20}\b/' => '<id>',
        '/\b[0-9a-f]{64}\b/' => '<file id>',
        // Send access ids (a UUID in base64url) and password hashes.
        '/^[A-Za-z0-9_-]{22}$/' => '<access id>',
        '/^[A-Za-z0-9_-]{43}$/' => '<hash>',
        // Organization API keys.
        '/^[A-Za-z0-9]{30}$/' => '<api key>',
        // Authenticator keys and recovery codes.
        '/^[A-Z2-7]{32}$/' => '<base32>',
        // The server time in TOTP errors.
        '/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/' => '<server time>',
        // Dates in mails, in the server's time zone.
        '/[A-Z][a-z]+day, [A-Z][a-z]+ [ \d]\d, \d{4} at \d{2}:\d{2}:\d{2} [AP]M \S+/' => '<datetime>',
        // Each server builds URLs with its own address.
        '#http://127\.0\.0\.1:\d+#' => '<host>',
    ];

    private static ?Client $client = null;

    protected function setUp(): void
    {
        if (! getenv('VW_REFERENCE_URL') || ! getenv('VW_SUBJECT_URL')) {
            $this->markTestSkipped('Set VW_REFERENCE_URL and VW_SUBJECT_URL to compare with Vaultwarden.');
        }
    }

    /**
     * Send the request to both servers and assert that they answer alike.
     *
     * @param  array<string, string>  $headers
     * @return array{Exchange, Exchange} Reference and subject
     */
    protected function assertSameResponses(string $method, string $path, array $headers = [], ?string $body = null): array
    {
        $reference = self::send((string) getenv('VW_REFERENCE_URL'), $method, $path, $headers, $body);
        $subject = self::send((string) getenv('VW_SUBJECT_URL'), $method, $path, $headers, $body);

        $this->assertSameExchange($reference, $subject, "{$method} {$path}");

        return [$reference, $subject];
    }

    /**
     * Run a flow of requests on both servers, each with its own state (tokens,
     * ids), and assert that every step answers alike.
     *
     * @param  callable(Server): array<string, Exchange>  $flow  The exchanges by step name
     * @return array{array<string, Exchange>, array<string, Exchange>} Reference and subject
     */
    protected function assertSameFlows(callable $flow): array
    {
        return $this->assertSameFlowsOn((string) getenv('VW_REFERENCE_URL'), (string) getenv('VW_SUBJECT_URL'), $flow);
    }

    /**
     * assertSameFlows on another pair of servers, such as the one with groups
     * and events enabled (VW_FEATURES_REFERENCE_URL and VW_FEATURES_SUBJECT_URL).
     *
     * @param  callable(Server): array<string, Exchange>  $flow  The exchanges by step name
     * @return array{array<string, Exchange>, array<string, Exchange>} Reference and subject
     */
    protected function assertSameFlowsOn(string $referenceUrl, string $subjectUrl, callable $flow, ?string $referenceMailDir = null, ?string $subjectMailDir = null): array
    {
        if ($referenceUrl === '' || $subjectUrl === '') {
            $this->markTestSkipped('This pair of servers is not configured.');
        }

        return $this->assertSameFlowsBetween(new Server($referenceUrl, $referenceMailDir), new Server($subjectUrl, $subjectMailDir), $flow);
    }

    /**
     * assertSameFlows on the default pair, with the hubs of the subject served
     * by its notifications daemon (VW_SUBJECT_NOTIFICATIONS_URL).
     *
     * @param  callable(Server): array<string, Exchange>  $flow  The exchanges by step name
     * @return array{array<string, Exchange>, array<string, Exchange>} Reference and subject
     */
    protected function assertSameNotificationFlows(callable $flow): array
    {
        if (! getenv('VW_SUBJECT_NOTIFICATIONS_URL')) {
            $this->markTestSkipped('Set VW_SUBJECT_NOTIFICATIONS_URL to compare the notification hubs.');
        }
        $reference = (string) getenv('VW_REFERENCE_URL');

        return $this->assertSameFlowsBetween(new Server($reference, notificationsUrl: $reference),
            new Server((string) getenv('VW_SUBJECT_URL'), notificationsUrl: (string) getenv('VW_SUBJECT_NOTIFICATIONS_URL')), $flow);
    }

    /**
     * assertSameFlows on the pair with groups and events, which also pushes
     * to the fake relays features-reference and features-subject.
     *
     * @param  callable(Server): array<string, Exchange>  $flow  The exchanges by step name
     * @return array{array<string, Exchange>, array<string, Exchange>} Reference and subject
     */
    protected function assertSamePushFlows(callable $flow): array
    {
        if (! getenv('VW_FEATURES_REFERENCE_URL') || ! getenv('VW_SERVICES_HOST')) {
            $this->markTestSkipped('This pair of servers is not configured.');
        }

        return $this->assertSameFlowsBetween(new Server((string) getenv('VW_FEATURES_REFERENCE_URL'), relay: 'features-reference'),
            new Server((string) getenv('VW_FEATURES_SUBJECT_URL'), relay: 'features-subject'), $flow);
    }

    /**
     * @param  callable(Server): array<string, Exchange>  $flow  The exchanges by step name
     * @return array{array<string, Exchange>, array<string, Exchange>} Reference and subject
     */
    protected function assertSameFlowsBetween(Server $referenceServer, Server $subjectServer, callable $flow): array
    {
        $reference = $flow($referenceServer);
        $subject = $flow($subjectServer);

        $this->assertSame(array_keys($reference), array_keys($subject), 'Steps of the flow');
        foreach ($reference as $step => $exchange) {
            $this->assertSameExchange($exchange, $subject[$step], $step);
        }

        return [$reference, $subject];
    }

    protected function assertSameExchange(Exchange $reference, Exchange $subject, string $label): void
    {
        $this->assertSame($reference->status, $subject->status, "Status of {$label}\nVaultwarden: {$reference->body}\nThis implementation: {$subject->body}");

        foreach (self::HEADERS as $header) {
            $this->assertSame($reference->header($header), $subject->header($header), "Header {$header} of {$label}");
        }
        $this->assertSame(
            self::cacheDirectives($reference->header('Cache-Control')),
            self::cacheDirectives($subject->header('Cache-Control')),
            "Cache-Control of {$label}",
        );

        $this->assertSame(self::normalizedBody($reference), self::normalizedBody($subject), "Body of {$label}");
    }

    /**
     * assertSameFlows on the pair of servers that send mail through SMTP
     * sinks (VW_MAIL_*); Server::mail() reads what they sent.
     *
     * @param  callable(Server): array<string, Exchange>  $flow  The exchanges by step name
     * @return array{array<string, Exchange>, array<string, Exchange>} Reference and subject
     */
    protected function assertSameMailFlows(callable $flow): array
    {
        return $this->assertSameFlowsOn((string) getenv('VW_MAIL_REFERENCE_URL'), (string) getenv('VW_MAIL_SUBJECT_URL'), $flow,
            (string) getenv('VW_MAIL_REFERENCE_DIR'), (string) getenv('VW_MAIL_SUBJECT_DIR'));
    }

    /**
     * A token signed with the RSA key all servers share (VW_RSA_KEY), as if
     * the servers had issued it for their default domain.
     *
     * @param  array<string, mixed>  $claims  In the field order of the Rust claims struct; iss is set
     */
    protected function signedToken(string $issuer, array $claims): string
    {
        $key = file_get_contents((string) getenv('VW_RSA_KEY'));
        if (! getenv('VW_RSA_KEY') || $key === false) {
            $this->markTestSkipped('Set VW_RSA_KEY to sign tokens.');
        }
        $claims['iss'] = "http://localhost|{$issuer}";
        $base64 = static fn (string $data): string => rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        $input = $base64('{"typ":"JWT","alg":"RS256"}').'.'.$base64((string) json_encode($claims, JSON_UNESCAPED_SLASHES));
        openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256);

        return $input.'.'.$base64(is_string($signature) ? $signature : '');
    }

    /**
     * @param  array<string, string>  $headers
     */
    public static function send(string $baseUrl, string $method, string $path, array $headers = [], ?string $body = null): Exchange
    {
        self::$client ??= new Client(['http_errors' => false, 'allow_redirects' => false, 'timeout' => 30]);

        $response = self::$client->request($method, rtrim($baseUrl, '/').$path, ['headers' => $headers, 'body' => $body]);

        $responseHeaders = [];
        foreach ($response->getHeaders() as $name => $values) {
            $responseHeaders[strtolower((string) $name)] = implode(', ', $values);
        }

        return new Exchange($response->getStatusCode(), $responseHeaders, (string) $response->getBody());
    }

    /**
     * JSON is decoded and encoded again, so that key order and the
     * difference between objects and lists still count but formatting does
     * not; other bodies are compared as text.
     */
    private static function normalizedBody(Exchange $exchange): string
    {
        if ($exchange->isJson() && $exchange->body !== '') {
            $decoded = json_decode($exchange->body);
            if (json_last_error() === JSON_ERROR_NONE) {
                return (string) json_encode(self::normalize($decoded), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            }
        }

        return self::normalizeString($exchange->body);
    }

    private static function normalize(mixed $value, int|string|null $key = null): mixed
    {
        return match (true) {
            is_array($value) => array_combine(array_keys($value), array_map(self::normalize(...), $value, array_keys($value))),
            $value instanceof \stdClass => (object) self::normalize(get_object_vars($value)),
            is_string($value) => self::normalizeString($value),
            // Computed after the token was made, so a second boundary may lie in between.
            $key === 'expires_in' && is_int($value) => '<seconds>',
            default => $value,
        };
    }

    private static function normalizeString(string $value): string
    {
        foreach (self::PLACEHOLDERS as $pattern => $placeholder) {
            $value = (string) preg_replace($pattern, $placeholder, $value);
        }

        return $value;
    }

    /**
     * @return list<string>
     */
    private static function cacheDirectives(?string $header): array
    {
        $directives = array_diff(array_map(trim(...), explode(',', strtolower((string) $header))), ['', 'private']);
        sort($directives);

        return $directives;
    }
}
