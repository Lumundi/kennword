<?php

/**
 * An SMTP server that never gets anywhere, for the transport's tests: it greets with one
 * byte every <interval> seconds and never ends the line, so that every single read
 * succeeds in time but the greeting never arrives. With "silent" it says nothing at all.
 *
 * Usage: php trickle-smtp.php <port> <interval>|silent
 */
[, $port, $mode] = $argv + [null, null, null];
$server = stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $error);
if ($server === false) {
    fwrite(STDERR, "Cannot listen on {$port}: {$error}\n");
    exit(1);
}

while (true) {
    $client = stream_socket_accept($server, -1);
    if ($client === false) {
        continue;
    }
    if ($mode === 'silent') {
        // Keep the connection open and say nothing.
        $held[] = $client;

        continue;
    }
    while (@fwrite($client, '2') !== false && is_resource($client) && ! feof($client)) {
        usleep((int) ((float) $mode * 1_000_000));
    }
}
