<?php

namespace App\Config;

use App\Database\DatabaseUrl;
use App\Logging\LogLevel;
use App\Support\CronSchedule;
use App\Support\EmailAddress;
use App\Support\EscapeDebug;
use App\Support\IpNetwork;
use Uri\WhatWg\Url as WhatWgUrl;

/**
 * validate_config (src/config.rs): the checks that keep Vaultwarden from
 * starting with an invalid configuration.
 */
final class ConfigValidator
{
    /**
     * i64::MAX >> 10
     */
    private const int MAX_FILESIZE_KB = PHP_INT_MAX >> 10;

    private const array SCHEDULES = [
        'send_purge_schedule',
        'trash_purge_schedule',
        'incomplete_2fa_schedule',
        'emergency_notification_reminder_schedule',
        'emergency_request_timeout_schedule',
        'event_cleanup_schedule',
        'auth_request_purge_schedule',
        'duo_context_purge_schedule',
        'purge_incomplete_sso_auth',
    ];

    private const array RATE_LIMITS = [
        'login_ratelimit_seconds' => 'must be at least 1 second',
        'login_ratelimit_max_burst' => 'must be at least 1',
        'admin_ratelimit_seconds' => 'must be at least 1 second',
        'admin_ratelimit_max_burst' => 'must be at least 1',
        'unauthenticated_ratelimit_seconds' => 'must be at least 1 second',
        'unauthenticated_ratelimit_max_burst' => 'must be at least 1',
    ];

    /**
     * @param  bool  $onUpdate  Settings saved in the admin panel are checked more strictly
     * @return list<string> Warnings
     *
     * @throws ConfigException
     */
    public static function validate(Config $config, bool $onUpdate = false): array
    {
        $warnings = [];

        $url = $config->string('database_url');
        if (DatabaseUrl::type($url, $config) === 'sqlite') {
            $file = str_starts_with($url, 'sqlite://') ? substr($url, strlen('sqlite://')) : $url;
            if (str_contains($file, '/')) {
                $parent = dirname(DatabaseUrl::sqlitePath($url, $config));
                if (! is_dir($parent)) {
                    self::fail("SQLite database directory `{$parent}` does not exist or is not a directory");
                }
            }
        }

        $proxies = trim($config->string('ip_header_trusted_proxies'));
        if (strcasecmp($proxies, 'all') !== 0 && strcasecmp($proxies, 'local') !== 0) {
            foreach (explode(',', $proxies) as $entry) {
                if (trim($entry) !== '' && IpNetwork::parse($entry) === null) {
                    self::fail('Invalid IP_HEADER_TRUSTED_PROXIES entry `'.trim($entry).'`, expected an IP or CIDR range');
                }
            }
        }

        if ($config->int('password_iterations') < 100_000) {
            self::fail('PASSWORD_ITERATIONS should be at least 100000 or higher. The default is 600000!');
        }

        foreach (['database_max_conns' => 'DATABASE_MAX_CONNS', 'database_min_conns' => 'DATABASE_MIN_CONNS'] as $name => $env) {
            if ($config->int($name) < 1 || $config->int($name) > 256) {
                self::fail("`{$env}` contains an invalid value. Ensure it is between 1 and 256.");
            }
        }
        if ($config->int('database_min_conns') > $config->int('database_max_conns')) {
            self::fail('`DATABASE_MIN_CONNS` must be less than or equal to `DATABASE_MAX_CONNS`.');
        }
        if ($config->int('database_timeout') < 1) {
            self::fail('`DATABASE_TIMEOUT` must be at least 1 second');
        }
        if ($config->int('database_idle_timeout') < 1) {
            self::fail('`DATABASE_IDLE_TIMEOUT` must be at least 1 second');
        }

        $logFile = $config->optionalString('log_file');
        if ($logFile !== null) {
            $handle = @fopen($config->absolutePath($logFile), 'a');
            if ($handle === false) {
                self::fail("Unable to write to log file: {$logFile}");
            }
            fclose($handle);
        }

        // Not validate_config, but init_logging (src/main.rs) refuses to start just the same.
        LogLevel::parse($config->string('log_level'));

        $domain = strtolower($config->string('domain'));
        if (! str_starts_with($domain, 'http://') && ! str_starts_with($domain, 'https://')) {
            self::fail("DOMAIN variable needs to contain the protocol (http, https). Use 'http[s]://bw.example.com' instead of 'bw.example.com'");
        }

        $rulesUrl = $config->string('fill_assist_rules_url');
        $parsed = WhatWgUrl::parse($rulesUrl);
        // Nothing to trim: str::trim goes by Unicode White_Space.
        if ($parsed === null || $parsed->getScheme() !== 'https' || ($parsed->getAsciiHost() ?? '') === '' || ($parsed->getUsername() ?? '') !== ''
            || ($parsed->getPassword() ?? '') !== '' || $parsed->getQuery() !== null || $parsed->getFragment() !== null
            || preg_match('/^\p{White_Space}|\p{White_Space}$/Du', $rulesUrl) === 1) {
            self::fail('`FILL_ASSIST_RULES_URL` must be a valid HTTPS URL without credentials, query parameters, fragments, or surrounding whitespace.');
        }

        foreach (preg_split('/\s+/', strtolower($config->string('allowed_connect_src')), flags: PREG_SPLIT_NO_EMPTY) ?: [] as $source) {
            if (! str_starts_with($source, 'https://') || ! Url::isValid($source)) {
                self::fail("ALLOWED_CONNECT_SRC variable contains one or more invalid URLs. Only FQDN's starting with https are allowed");
            }
        }

        $whitelist = $config->string('signups_domains_whitelist');
        if ($whitelist !== '' && in_array('', array_map(trim(...), explode(',', $whitelist)), true)) {
            self::fail('`SIGNUPS_DOMAINS_WHITELIST` contains empty tokens');
        }

        $orgCreationUsers = $config->string('org_creation_users');
        if (! in_array($orgCreationUsers, ['', 'all', 'none'], true)) {
            foreach (explode(',', $orgCreationUsers) as $user) {
                if (! str_contains($user, '@')) {
                    self::fail('`ORG_CREATION_USERS` contains invalid email addresses');
                }
            }
        }

        $adminToken = $config->optionalString('admin_token');
        if ($adminToken !== null && trim($adminToken) === '' && ! $config->bool('disable_admin_token')) {
            $warnings[] = '`ADMIN_TOKEN` is enabled but has an empty value, so the admin page will be disabled. '
                .'To enable the admin page without a token, use `DISABLE_ADMIN_TOKEN`.';
        }

        if ($config->bool('push_enabled')) {
            if ($config->string('push_installation_id') === '' || $config->string('push_installation_key') === '') {
                self::fail("Misconfigured Push Notification service\nIt looks like you enabled Push Notification feature, "
                    ."but didn't configure it properly. Make sure the installation id and key from https://bitwarden.com/host "
                    .'are added to your configuration.');
            }
            foreach (['push_relay_uri' => 'PUSH_RELAY_URI', 'push_identity_uri' => 'PUSH_IDENTITY_URI'] as $name => $env) {
                $uri = strtolower($config->string($name));
                if (! str_starts_with($uri, 'https://')) {
                    self::fail("`{$env}` must start with 'https://'.");
                }
                if (! Url::isValid($uri)) {
                    self::fail("Invalid URL format for `{$env}`.");
                }
            }
        }

        $invalidFlags = array_keys(FeatureFlags::parse($config->string('experimental_client_feature_flags'), 'invalid'));
        if ($invalidFlags !== []) {
            // Debug output of a HashMap<String, bool>, whose order is random in Rust, and of a &[&str].
            $invalid = array_map(fn (string $flag): string => EscapeDebug::debug($flag).': true', $invalidFlags);
            $message = 'Unrecognized experimental client feature flags: {'.implode(', ', $invalid)."}.\n"
                ."Please ensure all feature flags are spelled correctly and that they are supported in this version.\n"
                .'Supported flags: ['.implode(', ', array_map(EscapeDebug::debug(...), FeatureFlags::SUPPORTED))."]\n";
            if ($onUpdate) {
                self::fail($message);
            }
            $warnings[] = $message;
        }

        foreach (['user_attachment_limit' => 'USER_ATTACHMENT_LIMIT', 'org_attachment_limit' => 'ORG_ATTACHMENT_LIMIT', 'user_send_limit' => 'USER_SEND_LIMIT'] as $name => $env) {
            $limit = $config->optionalInt($name);
            if ($limit !== null && ($limit < 0 || $limit > self::MAX_FILESIZE_KB)) {
                self::fail("`{$env}` is out of bounds");
            }
        }

        $duo = array_map(static fn (string $name): bool => $config->optionalString($name) !== null, ['duo_host', 'duo_ikey', 'duo_skey']);
        if ($config->bool('_enable_duo') && in_array(true, $duo, true) && in_array(false, $duo, true)) {
            self::fail('All Duo options need to be set for global Duo support');
        }

        if ($config->bool('sso_enabled')) {
            self::validateSso($config);
        }

        if ($config->bool('_enable_yubico')) {
            if (($config->optionalString('yubico_client_id') !== null) !== ($config->optionalString('yubico_secret_key') !== null)) {
                self::fail('Both `YUBICO_CLIENT_ID` and `YUBICO_SECRET_KEY` must be set for Yubikey OTP support');
            }
            $server = $config->optionalString('yubico_server');
            if ($server !== null && ! str_starts_with(strtolower($server), 'https://')) {
                self::fail("`YUBICO_SERVER` must be a valid URL and start with 'https://'. Either unset this variable or provide a valid URL.");
            }
        }

        if ($config->bool('_enable_smtp')) {
            self::validateSmtp($config);
        }

        $email2fa = $config->bool('_enable_email_2fa');
        if ($email2fa && ! ($config->optionalString('smtp_host') !== null || $config->bool('use_sendmail'))) {
            self::fail('To enable email 2FA, a mail transport must be configured');
        }
        if (! $email2fa && $config->bool('email_2fa_enforce_on_verified_invite')) {
            self::fail('To enforce email 2FA on verified invitations, email 2fa has to be enabled!');
        }
        if (! $email2fa && $config->bool('email_2fa_auto_fallback')) {
            self::fail('To use email 2FA as automatic fallback, email 2fa has to be enabled!');
        }

        $blockRegex = $config->optionalString('http_request_block_regex');
        if ($blockRegex !== null && @preg_match("\x01{$blockRegex}\x01u", '') === false) {
            self::fail('`HTTP_REQUEST_BLOCK_REGEX` is invalid: '.preg_last_error_msg());
        }

        $iconService = $config->string('icon_service');
        if (! in_array($iconService, ['internal', 'bitwarden', 'duckduckgo', 'google'], true)) {
            if (! str_starts_with($iconService, 'http')) {
                self::fail("Icon service URL `{$iconService}` must start with \"http\"");
            }
            match (substr_count($iconService, '{}')) {
                1 => null,
                0 => self::fail("Icon service URL `{$iconService}` has no placeholder \"{}\""),
                default => self::fail("Icon service URL `{$iconService}` has more than one placeholder \"{}\""),
            };
        }

        if (! in_array($config->int('icon_redirect_code'), [301, 302, 307, 308], true)) {
            self::fail('Only HTTP 301/302 and 307/308 redirects are supported');
        }

        if ($config->int('invitation_expiration_hours') < 1) {
            self::fail('`INVITATION_EXPIRATION_HOURS` has a minimum duration of 1 hour');
        }

        $rememberDays = $config->int('two_factor_remember_days');
        if ($rememberDays < 1 || $rememberDays > 90) {
            self::fail('`TWO_FACTOR_REMEMBER_DAYS` must be between 1 and 90 days');
        }

        foreach (self::SCHEDULES as $name) {
            $schedule = $config->string($name);
            if ($schedule !== '' && ! CronSchedule::isValid($schedule)) {
                self::fail('`'.strtoupper($name).'` is not a valid cron expression');
            }
        }

        foreach (self::RATE_LIMITS as $name => $requirement) {
            if ($config->int($name) < 1) {
                self::fail('`'.strtoupper($name)."` {$requirement}");
            }
        }

        if (! $config->bool('disable_admin_token') && $adminToken !== null) {
            if (str_starts_with($adminToken, '$argon2')) {
                if (! self::isPhcString($adminToken)) {
                    self::fail("The configured Argon2 PHC in `ADMIN_TOKEN` is invalid: '{$adminToken}'");
                }
            } else {
                $warnings[] = 'You are using a plain text `ADMIN_TOKEN` which is insecure. Please generate a secure Argon2 PHC '
                    .'string by using `vaultwarden hash` or `argon2`.';
            }
        }

        if ($config->bool('increase_note_size_limit')) {
            $warnings[] = 'Secure Note size limit is increased to 100_000! This could cause issues with clients. '
                .'Also exports will not work on Bitwarden servers!.';
        }

        return $warnings;
    }

    /**
     * @throws ConfigException
     */
    private static function validateSso(Config $config): void
    {
        if ($config->string('sso_client_id') === '' || $config->string('sso_client_secret') === '' || $config->string('sso_authority') === '') {
            self::fail('`SSO_CLIENT_ID`, `SSO_CLIENT_SECRET` and `SSO_AUTHORITY` must be set for SSO support');
        }

        $authority = $config->string('sso_authority');
        if (! Url::isValid($authority)) {
            self::fail("Invalid sso_authority URL ({$authority})");
        }

        $callback = $config->string('sso_callback_path');
        if (! Url::isValid($callback)) {
            self::fail("Invalid sso_callback_path ({$callback} built using `domain`) URL");
        }

        $policy = $config->optionalString('sso_master_password_policy');
        if ($policy !== null) {
            $decoded = json_decode($policy);
            if (json_last_error() !== JSON_ERROR_NONE) {
                self::fail('Invalid sso_master_password_policy ('.json_last_error_msg()."), Ensure that it's correctly escaped with ''");
            }
            if (! is_object($decoded)) {
                self::fail('Invalid sso_master_password_policy: parsed value is not a JSON object');
            }
        }
    }

    /**
     * @throws ConfigException
     */
    private static function validateSmtp(Config $config): void
    {
        if (! in_array($config->string('smtp_security'), ['off', 'starttls', 'force_tls'], true)) {
            self::fail('`SMTP_SECURITY` is invalid. It needs to be one of the following options: starttls, force_tls or off');
        }

        $host = $config->optionalString('smtp_host');
        $from = $config->string('smtp_from');

        if ($config->bool('use_sendmail')) {
            $command = $config->optionalString('sendmail_command') ?? 'sendmail';
            $path = str_starts_with($command, '/') ? $command : self::which($command);
            if ($path === null) {
                self::fail("sendmail command {$command} not found in \$PATH");
            }
            if (! file_exists($path)) {
                self::fail('sendmail command not found at `'.EscapeDebug::debug($path).'`');
            }
            // The message is Vaultwarden's, although it is raised for a directory.
            if (is_dir($path)) {
                self::fail('sendmail command at `'.EscapeDebug::debug($path)."` isn't a directory");
            }
            if (! is_executable($path)) {
                self::fail('sendmail command at `'.EscapeDebug::debug($path)."` isn't executable");
            }
        } else {
            if (($host !== null) === ($from === '')) {
                self::fail('Both `SMTP_HOST` and `SMTP_FROM` need to be set for email support without `USE_SENDMAIL`');
            }
            if (($config->optionalString('smtp_username') !== null) !== ($config->optionalString('smtp_password') !== null)) {
                self::fail('Both `SMTP_USERNAME` and `SMTP_PASSWORD` need to be set to enable email authentication without `USE_SENDMAIL`');
            }
        }

        if (($host !== null || $config->bool('use_sendmail')) && ! EmailAddress::isValid($from)) {
            self::fail("SMTP_FROM '{$from}' is not a valid email address");
        }

        if ($config->bool('_enable_email_2fa') && $config->int('email_token_size') < 6) {
            self::fail('`EMAIL_TOKEN_SIZE` has a minimum size of 6');
        }
    }

    /**
     * Whether a string is in the PHC format the password-hash crate parses.
     */
    private static function isPhcString(string $hash): bool
    {
        $b64 = '[A-Za-z0-9\/+.-]';

        return preg_match(
            '/^\$[a-z0-9-]{1,32}(?:\$v=[0-9]+)?(?:\$[a-z0-9-]{1,32}='.$b64.'{1,64}(?:,[a-z0-9-]{1,32}='.$b64.'{1,64})*)?(?:\$'.$b64.'{4,64}(?:\$[A-Za-z0-9\/+]{10,86})?)?$/D',
            $hash,
        ) === 1;
    }

    private static function which(string $command): ?string
    {
        foreach (explode(PATH_SEPARATOR, getenv('PATH') ?: '') as $directory) {
            $path = rtrim($directory, '/').'/'.$command;
            if ($directory !== '' && is_file($path) && is_executable($path)) {
                return $path;
            }
        }

        return null;
    }

    /**
     * @throws ConfigException
     */
    private static function fail(string $message): never
    {
        throw new ConfigException($message);
    }
}
