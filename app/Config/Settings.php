<?php

namespace App\Config;

use App\Config\SettingType as T;
use Closure;

/**
 * Vaultwarden's settings in the order of `make_config!` (src/config.rs). The
 * order matters: auto and generated values are computed from the settings
 * built before them.
 */
final class Settings
{
    /** @var array<string, Setting>|null */
    private static ?array $all = null;

    /**
     * @return array<string, Setting> Keyed by name
     */
    public static function all(): array
    {
        if (self::$all !== null) {
            return self::$all;
        }

        $settings = [];
        foreach (self::definitions() as [$group, $name, $type, $editable, $action, $default]) {
            $settings[$name] = new Setting($name, $group, $type, $editable, $action, $default);
        }

        return self::$all = $settings;
    }

    /**
     * @return list<array{string, string, T, bool, 'def'|'auto'|'option'|'generated', string|int|bool|Closure|null}>
     */
    private static function definitions(): array
    {
        $string = static fn (array $c, string $name): string => is_string($c[$name] ?? null) ? $c[$name] : '';

        return [
            ['folders', 'data_folder', T::String, false, 'def', 'data'],
            ['folders', 'database_url', T::String, false, 'auto', static fn (array $c): string => 'sqlite://'.self::joinPath($string($c, 'data_folder'), 'db.sqlite3')],
            ['folders', 'icon_cache_folder', T::String, false, 'auto', static fn (array $c): string => self::joinPath($string($c, 'data_folder'), 'icon_cache')],
            ['folders', 'attachments_folder', T::String, false, 'auto', static fn (array $c): string => self::joinPath($string($c, 'data_folder'), 'attachments')],
            ['folders', 'sends_folder', T::String, false, 'auto', static fn (array $c): string => self::joinPath($string($c, 'data_folder'), 'sends')],
            ['folders', 'tmp_folder', T::String, false, 'auto', static fn (array $c): string => self::joinPath($string($c, 'data_folder'), 'tmp')],
            ['folders', 'templates_folder', T::String, false, 'auto', static fn (array $c): string => self::joinPath($string($c, 'data_folder'), 'templates')],
            ['folders', 'rsa_key_filename', T::String, false, 'auto', static fn (array $c): string => self::joinPath($string($c, 'data_folder'), 'rsa_key')],
            ['folders', 'web_vault_folder', T::String, false, 'def', 'web-vault/'],

            ['ws', 'enable_websocket', T::Bool, false, 'def', true],

            ['push', 'push_enabled', T::Bool, false, 'def', false],
            ['push', 'push_relay_uri', T::String, false, 'def', 'https://push.bitwarden.com'],
            ['push', 'push_identity_uri', T::String, false, 'def', 'https://identity.bitwarden.com'],
            ['push', 'push_installation_id', T::Pass, false, 'def', ''],
            ['push', 'push_installation_key', T::Pass, false, 'def', ''],

            ['jobs', 'job_poll_interval_ms', T::U32, false, 'def', 30_000],
            ['jobs', 'send_purge_schedule', T::String, false, 'def', '0 5 * * * *'],
            ['jobs', 'trash_purge_schedule', T::String, false, 'def', '0 5 0 * * *'],
            ['jobs', 'incomplete_2fa_schedule', T::String, false, 'def', '30 * * * * *'],
            ['jobs', 'emergency_notification_reminder_schedule', T::String, false, 'def', '0 3 * * * *'],
            ['jobs', 'emergency_request_timeout_schedule', T::String, false, 'def', '0 7 * * * *'],
            ['jobs', 'event_cleanup_schedule', T::String, false, 'def', '0 10 0 * * *'],
            ['jobs', 'auth_request_purge_schedule', T::String, false, 'def', '30 * * * * *'],
            ['jobs', 'duo_context_purge_schedule', T::String, false, 'def', '30 * * * * *'],
            ['jobs', 'purge_incomplete_sso_auth', T::String, false, 'def', '0 20 0 * * *'],

            ['settings', 'domain', T::String, true, 'def', 'http://localhost'],
            ['settings', 'domain_set', T::Bool, false, 'def', false],
            ['settings', 'domain_origin', T::String, false, 'auto', static fn (array $c): string => Url::origin($string($c, 'domain'))],
            ['settings', 'domain_path', T::String, false, 'auto', static fn (array $c): string => Url::pathWithoutTrailingSlash($string($c, 'domain'))],
            ['settings', 'web_vault_enabled', T::Bool, false, 'def', true],
            ['settings', 'sends_allowed', T::Bool, true, 'def', true],
            ['settings', 'fill_assist_rules_url', T::String, true, 'def', 'https://fillassist.bitwarden.com'],
            ['settings', 'hibp_api_key', T::Pass, true, 'option', null],
            ['settings', 'user_attachment_limit', T::I64, true, 'option', null],
            ['settings', 'org_attachment_limit', T::I64, true, 'option', null],
            ['settings', 'user_send_limit', T::I64, true, 'option', null],
            ['settings', 'trash_auto_delete_days', T::U16, true, 'option', null],
            ['settings', 'incomplete_2fa_time_limit', T::U16, true, 'def', 3],
            ['settings', 'disable_icon_download', T::Bool, true, 'def', false],
            ['settings', 'signups_allowed', T::Bool, true, 'def', true],
            ['settings', 'signups_verify', T::Bool, true, 'def', false],
            ['settings', 'signups_verify_resend_time', T::U32, true, 'def', 3_600],
            ['settings', 'signups_verify_resend_limit', T::U16, true, 'def', 6],
            ['settings', 'signups_domains_whitelist', T::String, true, 'def', ''],
            ['settings', 'org_events_enabled', T::Bool, false, 'def', false],
            ['settings', 'org_creation_users', T::String, true, 'def', ''],
            ['settings', 'invitations_allowed', T::Bool, true, 'def', true],
            ['settings', 'invitation_expiration_hours', T::U16, false, 'def', 120],
            ['settings', 'emergency_access_allowed', T::Bool, true, 'def', true],
            ['settings', 'email_change_allowed', T::Bool, true, 'def', true],
            ['settings', 'password_iterations', T::I32, true, 'def', 600_000],
            ['settings', 'password_hints_allowed', T::Bool, true, 'def', true],
            ['settings', 'show_password_hint', T::Bool, true, 'def', false],
            ['settings', 'admin_token', T::Pass, true, 'option', null],
            ['settings', 'invitation_org_name', T::String, true, 'def', 'Vaultwarden'],
            ['settings', 'events_days_retain', T::U16, false, 'option', null],

            ['client', 'client_suppress_onboarding', T::Bool, true, 'def', false],

            ['advanced', 'ip_header', T::String, true, 'def', 'X-Real-IP'],
            ['advanced', '_ip_header_enabled', T::Bool, false, 'generated', static fn (array $c): bool => strtolower(trim($string($c, 'ip_header'))) !== 'none'],
            ['advanced', 'ip_header_trusted_proxies', T::String, true, 'def', 'local'],
            ['advanced', 'icon_service', T::String, false, 'def', 'internal'],
            ['advanced', '_icon_service_url', T::String, false, 'generated', static fn (array $c): string => self::iconServiceUrl($string($c, 'icon_service'))],
            ['advanced', '_icon_service_csp', T::String, false, 'generated', static fn (array $c): string => self::iconServiceCsp($string($c, 'icon_service'), $string($c, '_icon_service_url'))],
            ['advanced', 'icon_redirect_code', T::U16, true, 'def', 302],
            ['advanced', 'icon_cache_ttl', T::U32, true, 'def', 2_592_000],
            ['advanced', 'icon_cache_negttl', T::U32, true, 'def', 259_200],
            ['advanced', 'icon_download_timeout', T::U16, true, 'def', 10],
            ['advanced', 'icon_blacklist_regex', T::String, false, 'option', null],
            ['advanced', 'icon_blacklist_non_global_ips', T::Bool, false, 'def', true],
            ['advanced', 'http_request_block_regex', T::String, true, 'option', null],
            ['advanced', 'http_request_block_non_global_ips', T::Bool, true, 'auto', static fn (array $c): bool => ($c['icon_blacklist_non_global_ips'] ?? false) === true],
            ['advanced', 'disable_2fa_remember', T::Bool, true, 'def', false],
            ['advanced', 'two_factor_remember_days', T::I64, true, 'def', 30],
            ['advanced', 'authenticator_disable_time_drift', T::Bool, true, 'def', false],
            ['advanced', 'experimental_client_feature_flags', T::String, false, 'def', ''],
            ['advanced', 'require_device_email', T::Bool, true, 'def', false],
            ['advanced', 'reload_templates', T::Bool, true, 'def', false],
            ['advanced', 'extended_logging', T::Bool, false, 'def', true],
            ['advanced', 'log_timestamp_format', T::String, true, 'def', '%Y-%m-%d %H:%M:%S.%3f'],
            ['advanced', 'use_syslog', T::Bool, false, 'def', false],
            ['advanced', 'log_file', T::String, false, 'option', null],
            ['advanced', 'log_level', T::String, false, 'def', 'info'],
            ['advanced', 'enable_db_wal', T::Bool, false, 'def', true],
            ['advanced', 'db_connection_retries', T::U32, false, 'def', 15],
            ['advanced', 'database_timeout', T::U32, false, 'def', 30],
            ['advanced', 'database_idle_timeout', T::U32, false, 'def', 600],
            ['advanced', 'database_max_conns', T::U32, false, 'def', 10],
            ['advanced', 'database_min_conns', T::U32, false, 'def', 2],
            ['advanced', 'database_conn_init', T::String, false, 'def', ''],
            ['advanced', 'disable_admin_token', T::Bool, false, 'def', false],
            ['advanced', 'allowed_iframe_ancestors', T::String, true, 'def', ''],
            ['advanced', 'allowed_connect_src', T::String, true, 'def', ''],
            ['advanced', 'login_ratelimit_seconds', T::U16, false, 'def', 60],
            ['advanced', 'login_ratelimit_max_burst', T::U16, false, 'def', 10],
            ['advanced', 'unauthenticated_ratelimit_seconds', T::U16, false, 'def', 60],
            ['advanced', 'unauthenticated_ratelimit_max_burst', T::U16, false, 'def', 50],
            ['advanced', 'admin_ratelimit_seconds', T::U16, false, 'def', 300],
            ['advanced', 'admin_ratelimit_max_burst', T::U16, false, 'def', 3],
            ['advanced', 'admin_session_lifetime', T::U32, true, 'def', 20],
            ['advanced', 'org_groups_enabled', T::Bool, false, 'def', false],
            ['advanced', 'increase_note_size_limit', T::Bool, true, 'def', false],
            ['advanced', '_max_note_size', T::Usize, false, 'generated', static fn (array $c): int => ($c['increase_note_size_limit'] ?? false) === true ? 100_000 : 10_000],
            ['advanced', 'enforce_single_org_with_reset_pw_policy', T::Bool, false, 'def', false],
            ['advanced', 'dns_prefer_ipv6', T::Bool, true, 'def', false],

            ['sso', 'sso_enabled', T::Bool, true, 'def', false],
            ['sso', 'sso_only', T::Bool, true, 'def', false],
            ['sso', 'sso_signups_allowed', T::Bool, true, 'def', true],
            ['sso', 'sso_signups_match_email', T::Bool, true, 'def', true],
            ['sso', 'sso_allow_unknown_email_verification', T::Bool, true, 'def', false],
            ['sso', 'sso_client_id', T::String, true, 'def', ''],
            ['sso', 'sso_client_secret', T::Pass, true, 'def', ''],
            ['sso', 'sso_authority', T::String, true, 'def', ''],
            ['sso', 'sso_scopes', T::String, true, 'def', 'email profile'],
            ['sso', 'sso_authorize_extra_params', T::String, true, 'def', ''],
            ['sso', 'sso_pkce', T::Bool, true, 'def', true],
            ['sso', 'sso_audience_trusted', T::String, true, 'option', null],
            ['sso', 'sso_callback_path', T::String, true, 'generated', static fn (array $c): string => rtrim($string($c, 'domain'), '/').'/identity/connect/oidc-signin'],
            ['sso', 'sso_master_password_policy', T::String, true, 'option', null],
            ['sso', 'sso_auth_only_not_session', T::Bool, true, 'def', false],
            ['sso', 'sso_client_cache_expiration', T::U32, true, 'def', 0],
            ['sso', 'sso_debug_tokens', T::Bool, true, 'def', false],

            ['yubico', '_enable_yubico', T::Bool, true, 'def', true],
            ['yubico', 'yubico_client_id', T::String, true, 'option', null],
            ['yubico', 'yubico_secret_key', T::Pass, true, 'option', null],
            ['yubico', 'yubico_server', T::String, true, 'option', null],

            ['duo', '_enable_duo', T::Bool, true, 'def', true],
            ['duo', 'duo_ikey', T::String, true, 'option', null],
            ['duo', 'duo_skey', T::Pass, true, 'option', null],
            ['duo', 'duo_host', T::String, true, 'option', null],

            ['smtp', '_enable_smtp', T::Bool, true, 'def', true],
            ['smtp', 'use_sendmail', T::Bool, true, 'def', false],
            ['smtp', 'sendmail_command', T::String, false, 'option', null],
            ['smtp', 'smtp_host', T::String, true, 'option', null],
            ['smtp', 'smtp_ssl', T::Bool, false, 'option', null],
            ['smtp', 'smtp_explicit_tls', T::Bool, false, 'option', null],
            ['smtp', 'smtp_security', T::String, true, 'auto', static fn (array $c): string => self::smtpSecurity($c['smtp_ssl'] ?? null, $c['smtp_explicit_tls'] ?? null)],
            ['smtp', 'smtp_port', T::U16, true, 'auto', static fn (array $c): int => match ($c['smtp_security'] ?? null) {
                'force_tls' => 465,
                'starttls' => 587,
                default => 25,
            }],
            ['smtp', 'smtp_from', T::String, true, 'def', ''],
            ['smtp', 'smtp_from_name', T::String, true, 'def', 'Vaultwarden'],
            ['smtp', 'smtp_username', T::String, true, 'option', null],
            ['smtp', 'smtp_password', T::Pass, true, 'option', null],
            ['smtp', 'smtp_auth_mechanism', T::String, true, 'option', null],
            ['smtp', 'smtp_timeout', T::U16, true, 'def', 15],
            ['smtp', 'helo_name', T::String, true, 'option', null],
            ['smtp', 'smtp_embed_images', T::Bool, true, 'def', true],
            ['smtp', '_smtp_img_src', T::String, false, 'generated', static fn (array $c): string => ($c['smtp_embed_images'] ?? false) === true
                ? 'cid:'
                : rtrim($string($c, 'domain'), '/').'/vw_static/'],
            ['smtp', 'smtp_debug', T::Bool, false, 'def', false],
            ['smtp', 'smtp_accept_invalid_certs', T::Bool, true, 'def', false],
            ['smtp', 'smtp_accept_invalid_hostnames', T::Bool, true, 'def', false],

            ['email_2fa', '_enable_email_2fa', T::Bool, true, 'auto', static fn (array $c): bool => ($c['_enable_smtp'] ?? false) === true
                && (($c['smtp_host'] ?? null) !== null || ($c['use_sendmail'] ?? false) === true)],
            ['email_2fa', 'email_token_size', T::U8, true, 'def', 6],
            ['email_2fa', 'email_expiration_time', T::U32, true, 'def', 600],
            ['email_2fa', 'email_attempts_limit', T::U8, true, 'def', 3],
            ['email_2fa', 'email_2fa_enforce_on_verified_invite', T::Bool, true, 'def', false],
            ['email_2fa', 'email_2fa_auto_fallback', T::Bool, true, 'def', false],
        ];
    }

    /**
     * storage::join_path for local paths.
     */
    public static function joinPath(string $base, string $child): string
    {
        $base = rtrim($base, '/');
        $child = ltrim($child, '/');

        return match (true) {
            $base === '' => $child,
            $child === '' => $base,
            default => "{$base}/{$child}",
        };
    }

    /**
     * generate_icon_service_url
     */
    private static function iconServiceUrl(string $service): string
    {
        return match ($service) {
            'internal' => '',
            'bitwarden' => 'https://icons.bitwarden.net/{}/icon.png',
            'duckduckgo' => 'https://icons.duckduckgo.com/ip3/{}.ico',
            'google' => 'https://www.google.com/s2/favicons?domain={}&sz=32',
            default => $service,
        };
    }

    /**
     * generate_icon_service_csp: everything before the first `{` is the fixed part of the URL.
     */
    private static function iconServiceCsp(string $service, string $url): string
    {
        $position = strpos($url, '{');
        $csp = $position === false ? '' : substr($url, 0, $position);

        // Google redirects once more to its gstatic.com domain.
        return $service === 'google' ? $csp.' https://*.gstatic.com/favicon' : $csp;
    }

    /**
     * smtp_convert_deprecated_ssl_options
     */
    private static function smtpSecurity(mixed $ssl, mixed $explicitTls): string
    {
        return match (true) {
            $explicitTls === true => 'force_tls',
            $ssl === false => 'off',
            default => 'starttls',
        };
    }
}
