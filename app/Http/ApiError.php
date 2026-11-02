<?php

namespace App\Http;

use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use stdClass;

/**
 * Vaultwarden's error type (src/error.rs) and the JSON it responds with,
 * by default with status 400.
 */
final class ApiError extends RuntimeException
{
    /**
     * @param  'simple'|'compact'|'empty'|'json'  $kind
     */
    private function __construct(
        string $message,
        public readonly int $status,
        public readonly string $kind,
        public readonly mixed $body = null,
        public readonly ?string $logMessage = null,
        public readonly ?int $event = null,
        public readonly bool $silent = false,
    ) {
        parent::__construct($message);
    }

    /**
     * err!(message), err!(message, log value), err_code!(message, status) and
     * errors converted with `?`, whose message is the name of their kind
     * ("Db", "Serde", ...). The log value only goes to the log; the event
     * (ErrorEvent) goes to the event log of failed logins.
     */
    public static function message(string $message, int $status = 400, ?string $logMessage = null, ?int $event = null): self
    {
        return new self($message, $status, 'simple', logMessage: $logMessage, event: $event);
    }

    /**
     * err_silent!(message): the same error, but nothing goes to the log.
     */
    public static function silent(string $message, int $status = 400, ?int $event = null): self
    {
        return new self($message, $status, 'simple', event: $event, silent: true);
    }

    /**
     * err!(Compact, message): the shorter error model of newer endpoints.
     */
    public static function compact(string $message, int $status = 400): self
    {
        return new self($message, $status, 'compact');
    }

    /**
     * Error::empty(): an empty JSON object.
     */
    public static function empty(int $status = 400): self
    {
        return new self('', $status, 'empty');
    }

    /**
     * err_json!(value, log message): the value itself, for 2FA and similar responses.
     */
    public static function json(mixed $body, string $logMessage, int $status = 400): self
    {
        return new self($logMessage, $status, 'json', $body);
    }

    public function withStatus(int $status): self
    {
        return new self($this->message, $status, $this->kind, $this->body, $this->logMessage, $this->event, $this->silent);
    }

    /**
     * Error::message(): what the user is told, which bulk responses show per
     * item. Error::empty() carries the name of its kind.
     */
    public function userMessage(): string
    {
        return $this->kind === 'empty' ? 'Empty' : $this->message;
    }

    /**
     * The error's Debug formatting: the message, followed by the log value
     * when there is one.
     */
    public function debugText(): string
    {
        return match ($this->kind) {
            'empty' => '',
            'json' => $this->message,
            default => $this->logMessage === null ? $this->message : "{$this->message}. {$this->logMessage}",
        };
    }

    /**
     * The error's Display formatting, which `{e}` shows: the JSON it responds with.
     */
    public function displayText(): string
    {
        return (string) $this->toResponse()->getContent();
    }

    /**
     * err! logs the message, without a stack trace.
     */
    public function report(): void
    {
        if ($this->silent) {
            return;
        }
        Log::error($this->logMessage === null ? $this->message : "{$this->message}. {$this->logMessage}");
    }

    public function toResponse(): Response
    {
        $message = $this->message;

        // ApiErrorResponse and CompactApiErrorResponse serialize their fields in this order.
        $body = match ($this->kind) {
            'simple' => [
                'message' => $message,
                'validationErrors' => ['' => [$message]],
                'errorModel' => ['message' => $message, 'object' => 'error'],
                'error' => '',
                'error_description' => '',
                'exceptionMessage' => null,
                'exceptionStackTrace' => null,
                'innerExceptionMessage' => null,
                'object' => 'error',
            ],
            'compact' => [
                'message' => $message,
                'validationErrors' => null,
                'exceptionMessage' => null,
                'exceptionStackTrace' => null,
                'innerExceptionMessage' => null,
                'object' => 'error',
            ],
            'empty' => new stdClass,
            default => $this->body,
        };

        return Json::response($body, $this->status);
    }
}
