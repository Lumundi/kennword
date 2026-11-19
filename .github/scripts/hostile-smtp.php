<?php

/**
 * An SMTP server that misbehaves at once, for the transport's tests (lettre's tests of
 * the same cases):
 *
 * - starttls: offers STARTTLS and appends replies of its own to the reply to it, in the
 *   same write, as someone between client and server could; it never starts TLS.
 * - endless-line: greets with a line that does not end.
 * - endless-reply: greets with a reply whose lines do not stop ("220-...").
 *
 * Each command it receives is appended to <log>, when given, and "EOF" once the client
 * has closed the connection (starttls only).
 *
 * Usage: php hostile-smtp.php <port> <mode> [log]
 */
[, $port, $mode, $log] = $argv + [null, null, null, null];
$server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $error);
if ($server === false) {
    fwrite(STDERR, "Cannot listen on {$port}: {$error}\n");
    exit(1);
}

$received = static function ($client) use ($log): string|false {
    $line = fgets($client);
    if ($line !== false && $log !== null) {
        file_put_contents($log, $line, FILE_APPEND);
    }

    return $line;
};

// "Endless" is ten times what the client may take, then silence until it hangs up: a client
// without the limit fails with a timeout instead of filling its memory.
$flood = static function ($client, string $chunk): void {
    for ($sent = 0; $sent < 1_000_000; $sent += strlen($chunk)) {
        if (@fwrite($client, $chunk) === false) {
            return;
        }
    }
    while (! feof($client) && @fread($client, 8192) !== false) {
    }
};

while (true) {
    $client = stream_socket_accept($server, -1);
    if ($client === false) {
        continue;
    }

    switch ($mode) {
        case 'starttls':
            fwrite($client, "220 localhost ESMTP\r\n");
            if ($received($client) === false) {
                // A probe whether the server is up.
                break;
            }
            fwrite($client, "250-localhost\r\n250 STARTTLS\r\n");
            $received($client);
            fwrite($client, "220 go ahead\r\n250-forged.example\r\n250 AUTH PLAIN\r\n");
            // Take whatever else comes, until the client gives up.
            while ($received($client) !== false) {
            }
            if ($log !== null) {
                file_put_contents($log, "EOF\n", FILE_APPEND);
            }
            break;
        case 'endless-line':
            fwrite($client, '220 ');
            $flood($client, str_repeat('x', 8192));
            break;
        case 'endless-reply':
            $flood($client, str_repeat("220-localhost\r\n", 512));
            break;
    }
    fclose($client);
}
