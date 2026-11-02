<?php

namespace App\Logging;

use Monolog\Formatter\LineFormatter;
use Monolog\LogRecord;

/**
 * The log lines of init_logging (src/main.rs): with EXTENDED_LOGGING
 * `[<time>][<target>][<LEVEL>] <message>`, the time in LOG_TIMESTAMP_FORMAT,
 * otherwise the message alone. Rust's log crate knows the levels ERROR,
 * WARN, INFO, DEBUG and TRACE; Monolog's others are mapped onto them. The
 * target is "kennword", where Vaultwarden names its Rust module.
 */
final class VaultwardenFormatter extends LineFormatter
{
    private const array LEVELS = [
        'EMERGENCY' => 'ERROR', 'ALERT' => 'ERROR', 'CRITICAL' => 'ERROR', 'ERROR' => 'ERROR',
        'WARNING' => 'WARN', 'NOTICE' => 'INFO', 'INFO' => 'INFO', 'DEBUG' => 'DEBUG',
    ];

    public function __construct(private readonly bool $extended = true, string $timestampFormat = '%Y-%m-%d %H:%M:%S.%3f')
    {
        parent::__construct($extended ? "[%datetime%][kennword][%level_name%] %message% %context% %extra%\n" : "%message% %context% %extra%\n",
            Strftime::toDateFormat($timestampFormat), allowInlineLineBreaks: true, ignoreEmptyContextAndExtra: true);
    }

    public function format(LogRecord $record): string
    {
        // Without context and extra only the spaces before them would be left.
        $line = rtrim(parent::format($record), " \n")."\n";
        if (! $this->extended) {
            return $line;
        }
        $level = $record->level->getName();

        return str_replace("][{$level}] ", ']['.self::LEVELS[$level].'] ', $line);
    }
}
