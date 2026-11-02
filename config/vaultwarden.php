<?php

// Vaultwarden's own settings (DATA_FOLDER, DOMAIN, ...) are not Laravel
// configuration; they are read like Vaultwarden reads them, see
// App\Config\Config.

return [

    /*
    |--------------------------------------------------------------------------
    | Upstream versions
    |--------------------------------------------------------------------------
    |
    | The Vaultwarden release and web vault build this implementation mirrors
    | (see parity/reference.json). Templates compare the release through the
    | "vwver" helper; "webver" compares the version of the installed web vault
    | (App\Support\WebVault), like Vaultwarden.
    |
    */

    'version' => '1.37.5',

    'web_vault_version' => '2026.10.1',

    /*
    |--------------------------------------------------------------------------
    | Notifications daemon
    |--------------------------------------------------------------------------
    |
    | Where requests hand their live notifications to the daemon
    | (php artisan vaultwarden:notifications) and where it listens for them:
    | unix:///path/to/socket or tcp://127.0.0.1:port. Null means the Unix
    | socket notifications.sock in DATA_FOLDER.
    |
    */

    'notifications_socket' => env('NOTIFICATIONS_SOCKET'),

];
