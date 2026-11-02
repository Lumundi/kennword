<?php

namespace Tests\Unit\Config;

use App\Config\Config;
use App\Config\ConfigException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * validate_config: what keeps Vaultwarden from starting.
 */
class ConfigValidatorTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir().'/vw-validate-'.bin2hex(random_bytes(6));
        mkdir($this->base.'/data', recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->base));
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function invalidConfigurations(): iterable
    {
        yield 'sqlite folder missing' => [['DATABASE_URL' => 'sqlite://missing/db.sqlite3'], 'SQLite database directory'];
        yield 'unknown database scheme' => [['DATABASE_URL' => 'mariadb://db/vault'], 'does not match any known database scheme'];
        yield 'trusted proxy' => [['IP_HEADER_TRUSTED_PROXIES' => '10.0.0.0/8, proxy.local'], 'Invalid IP_HEADER_TRUSTED_PROXIES entry `proxy.local`'];
        yield 'password iterations' => [['PASSWORD_ITERATIONS' => '99999'], 'PASSWORD_ITERATIONS should be at least 100000'];
        yield 'max connections' => [['DATABASE_MAX_CONNS' => '257'], '`DATABASE_MAX_CONNS` contains an invalid value'];
        yield 'min above max' => [['DATABASE_MIN_CONNS' => '20'], '`DATABASE_MIN_CONNS` must be less than or equal to `DATABASE_MAX_CONNS`.'];
        yield 'database timeout' => [['DATABASE_TIMEOUT' => '0'], '`DATABASE_TIMEOUT` must be at least 1 second'];
        yield 'domain without protocol' => [['DOMAIN' => 'vault.example.com'], 'DOMAIN variable needs to contain the protocol'];
        yield 'fill assist over http' => [['FILL_ASSIST_RULES_URL' => 'http://rules.example'], '`FILL_ASSIST_RULES_URL` must be a valid HTTPS URL without credentials, query parameters, fragments, or surrounding whitespace.'];
        yield 'fill assist with credentials' => [['FILL_ASSIST_RULES_URL' => 'https://user@rules.example'], '`FILL_ASSIST_RULES_URL` must be a valid HTTPS URL without credentials, query parameters, fragments, or surrounding whitespace.'];
        yield 'fill assist with a password' => [['FILL_ASSIST_RULES_URL' => 'https://:secret@rules.example'], '`FILL_ASSIST_RULES_URL` must be a valid HTTPS URL without credentials, query parameters, fragments, or surrounding whitespace.'];
        yield 'fill assist with a query' => [['FILL_ASSIST_RULES_URL' => 'https://rules.example/?'], '`FILL_ASSIST_RULES_URL` must be a valid HTTPS URL without credentials, query parameters, fragments, or surrounding whitespace.'];
        yield 'fill assist with a fragment' => [['FILL_ASSIST_RULES_URL' => 'https://rules.example/#rules'], '`FILL_ASSIST_RULES_URL` must be a valid HTTPS URL without credentials, query parameters, fragments, or surrounding whitespace.'];
        yield 'fill assist with whitespace' => [['FILL_ASSIST_RULES_URL' => "https://rules.example\u{a0}"], '`FILL_ASSIST_RULES_URL` must be a valid HTTPS URL without credentials, query parameters, fragments, or surrounding whitespace.'];
        yield 'fill assist without a host' => [['FILL_ASSIST_RULES_URL' => 'https://'], '`FILL_ASSIST_RULES_URL` must be a valid HTTPS URL without credentials, query parameters, fragments, or surrounding whitespace.'];
        yield 'connect src over http' => [['ALLOWED_CONNECT_SRC' => 'https://a.example http://b.example'], 'ALLOWED_CONNECT_SRC variable contains one or more invalid URLs'];
        yield 'whitelist empty token' => [['SIGNUPS_DOMAINS_WHITELIST' => 'example.com,,example.org'], '`SIGNUPS_DOMAINS_WHITELIST` contains empty tokens'];
        yield 'org creation users' => [['ORG_CREATION_USERS' => 'admin@example.com,admin'], '`ORG_CREATION_USERS` contains invalid email addresses'];
        yield 'push without installation' => [['PUSH_ENABLED' => 'true'], 'Misconfigured Push Notification service'];
        yield 'push relay over http' => [['PUSH_ENABLED' => 'true', 'PUSH_INSTALLATION_ID' => 'id', 'PUSH_INSTALLATION_KEY' => 'key', 'PUSH_RELAY_URI' => 'http://push.example'], "`PUSH_RELAY_URI` must start with 'https://'."];
        yield 'attachment limit' => [['USER_ATTACHMENT_LIMIT' => '-1'], '`USER_ATTACHMENT_LIMIT` is out of bounds'];
        yield 'partial duo' => [['DUO_IKEY' => 'ikey'], 'All Duo options need to be set for global Duo support'];
        yield 'sso without client' => [['SSO_ENABLED' => 'true'], '`SSO_CLIENT_ID`, `SSO_CLIENT_SECRET` and `SSO_AUTHORITY` must be set for SSO support'];
        yield 'sso password policy' => [['SSO_ENABLED' => 'true', 'SSO_CLIENT_ID' => 'id', 'SSO_CLIENT_SECRET' => 'secret', 'SSO_AUTHORITY' => 'https://id.example', 'SSO_MASTER_PASSWORD_POLICY' => '[1]'], 'parsed value is not a JSON object'];
        yield 'yubico id only' => [['YUBICO_CLIENT_ID' => 'id'], 'Both `YUBICO_CLIENT_ID` and `YUBICO_SECRET_KEY` must be set'];
        yield 'yubico server' => [['YUBICO_SERVER' => 'http://yubico.example'], "`YUBICO_SERVER` must be a valid URL and start with 'https://'."];
        yield 'smtp security' => [['SMTP_SECURITY' => 'ssl'], '`SMTP_SECURITY` is invalid.'];
        yield 'smtp host without from' => [['SMTP_HOST' => 'smtp.example.com'], 'Both `SMTP_HOST` and `SMTP_FROM` need to be set'];
        yield 'smtp username only' => [['SMTP_HOST' => 'smtp.example.com', 'SMTP_FROM' => 'v@example.com', 'SMTP_USERNAME' => 'user'], 'Both `SMTP_USERNAME` and `SMTP_PASSWORD` need to be set'];
        yield 'smtp from' => [['SMTP_HOST' => 'smtp.example.com', 'SMTP_FROM' => 'vault'], "SMTP_FROM 'vault' is not a valid email address"];
        yield 'email token size' => [['SMTP_HOST' => 'smtp.example.com', 'SMTP_FROM' => 'v@example.com', 'EMAIL_TOKEN_SIZE' => '5'], '`EMAIL_TOKEN_SIZE` has a minimum size of 6'];
        yield 'sendmail missing' => [['USE_SENDMAIL' => 'true', 'SENDMAIL_COMMAND' => 'no-such-sendmail-command', 'SMTP_FROM' => 'v@example.com'], 'sendmail command no-such-sendmail-command not found in $PATH'];
        yield 'sendmail path' => [['USE_SENDMAIL' => 'true', 'SENDMAIL_COMMAND' => "/no/such/o'neil\tsendmail", 'SMTP_FROM' => 'v@example.com'],
            "sendmail command not found at `\"/no/such/o'neil\\tsendmail\"`"];
        yield 'email 2fa without transport' => [['_ENABLE_EMAIL_2FA' => 'true'], 'To enable email 2FA, a mail transport must be configured'];
        yield 'email 2fa fallback' => [['EMAIL_2FA_AUTO_FALLBACK' => 'true'], 'To use email 2FA as automatic fallback, email 2fa has to be enabled!'];
        yield 'block regex' => [['HTTP_REQUEST_BLOCK_REGEX' => '(unclosed'], '`HTTP_REQUEST_BLOCK_REGEX` is invalid'];
        yield 'icon service scheme' => [['ICON_SERVICE' => 'icons.example/{}'], 'must start with "http"'];
        yield 'icon service placeholder' => [['ICON_SERVICE' => 'https://icons.example/'], 'has no placeholder "{}"'];
        yield 'icon service placeholders' => [['ICON_SERVICE' => 'https://icons.example/{}/{}'], 'has more than one placeholder "{}"'];
        yield 'icon redirect code' => [['ICON_REDIRECT_CODE' => '303'], 'Only HTTP 301/302 and 307/308 redirects are supported'];
        yield 'invitation hours' => [['INVITATION_EXPIRATION_HOURS' => '0'], '`INVITATION_EXPIRATION_HOURS` has a minimum duration of 1 hour'];
        yield 'no remember days' => [['TWO_FACTOR_REMEMBER_DAYS' => '0'], '`TWO_FACTOR_REMEMBER_DAYS` must be between 1 and 90 days'];
        yield 'too many remember days' => [['TWO_FACTOR_REMEMBER_DAYS' => '91'], '`TWO_FACTOR_REMEMBER_DAYS` must be between 1 and 90 days'];
        yield 'schedule' => [['TRASH_PURGE_SCHEDULE' => '0 5 0 * *'], '`TRASH_PURGE_SCHEDULE` is not a valid cron expression'];
        yield 'rate limit' => [['LOGIN_RATELIMIT_MAX_BURST' => '0'], '`LOGIN_RATELIMIT_MAX_BURST` must be at least 1'];
        yield 'argon2 admin token' => [['ADMIN_TOKEN' => '$argon2id$broken token'], 'The configured Argon2 PHC in `ADMIN_TOKEN` is invalid'];
        yield 'log level' => [['LOG_LEVEL' => 'Warning'], 'LOG_LEVEL should follow the format info,vaultwarden::api::icons=debug, invalid: warning'];
    }

    /**
     * @param  array<string, string>  $env
     */
    #[DataProvider('invalidConfigurations')]
    public function test_invalid_configurations_are_refused(array $env, string $message): void
    {
        $this->expectException(ConfigException::class);
        $this->expectExceptionMessage($message);

        $this->load($env);
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function validConfigurations(): iterable
    {
        yield 'defaults' => [[]];
        yield 'trusted proxies' => [['IP_HEADER_TRUSTED_PROXIES' => '10.0.0.0/8, ::1, 192.168.1.1']];
        yield 'mysql' => [['DATABASE_URL' => 'mysql://user:pass@db/vault']];
        yield 'smtp' => [['SMTP_HOST' => 'smtp.example.com', 'SMTP_FROM' => 'vault@example.com', 'SMTP_USERNAME' => 'u', 'SMTP_PASSWORD' => 'p']];
        yield 'sso' => [['SSO_ENABLED' => 'true', 'SSO_CLIENT_ID' => 'id', 'SSO_CLIENT_SECRET' => 'secret', 'SSO_AUTHORITY' => 'https://id.example/realms/vault', 'SSO_MASTER_PASSWORD_POLICY' => '{"minLength":12}']];
        yield 'custom icon service' => [['ICON_SERVICE' => 'https://icons.example/{}.png', 'ICON_REDIRECT_CODE' => '308']];
        yield 'schedules' => [['SEND_PURGE_SCHEDULE' => '', 'TRASH_PURGE_SCHEDULE' => '0 */15 8-18 * * Mon-Fri', 'EVENT_CLEANUP_SCHEDULE' => '@daily']];
        yield 'argon2 admin token' => [['ADMIN_TOKEN' => '$argon2id$v=19$m=65540,t=3,p=4$MmeKRnGK5RW5mJS7h3TOL89GrpLPXJPAtTK8FTqj9HM$DqsstvoSAETl9YhnsXbf43WeaUwJC6JhViIvuPoig78']];
        yield 'disabled admin token' => [['DISABLE_ADMIN_TOKEN' => 'true', 'ADMIN_TOKEN' => '$argon2id$broken token']];
        yield 'log level for modules' => [['LOG_LEVEL' => 'info,vaultwarden::api::icons=debug']];
        // An empty user and password are none, like url's; a C0 control is no White_Space for str::trim.
        yield 'fill assist rules' => [['FILL_ASSIST_RULES_URL' => 'https://:@rules.example/feeds/', 'TWO_FACTOR_REMEMBER_DAYS' => '90']];
        yield 'fill assist with a control character' => [['FILL_ASSIST_RULES_URL' => "\x01https://rules.example", 'TWO_FACTOR_REMEMBER_DAYS' => '1']];
    }

    /**
     * @param  array<string, string>  $env
     */
    #[DataProvider('validConfigurations')]
    public function test_valid_configurations_are_accepted(array $env): void
    {
        $this->assertInstanceOf(Config::class, $this->load($env));
    }

    public function test_warnings_do_not_refuse_the_configuration(): void
    {
        $config = $this->load([
            'ADMIN_TOKEN' => 'plain-text',
            'INCREASE_NOTE_SIZE_LIMIT' => 'true',
            'EXPERIMENTAL_CLIENT_FEATURE_FLAGS' => 'ssh-agent-v2, unknown-flag',
        ]);

        $this->assertCount(3, $config->warnings);
        $this->assertStringStartsWith('Unrecognized experimental client feature flags: {"unknown-flag": true}.', $config->warnings[0]);
        $this->assertStringEndsWith('Supported flags: ["pm-5594-safari-account-switching", "pm-32413-multi-client-password-management", '
            .'"undetermined-cipher-scenario-logic", "enable-basic-auth-response", "fill-assist-targeting-rules", "ssh-agent-v2", "windows-desktop-autotype", '
            .'"windows-desktop-autotype-ga", "biometrics-sdk-ipc", "windows-native-credential-sync", "pm-34171-card-scanner", '
            ."\"pm-30529-webauthn-related-origins\", \"pm-32009-new-item-types\"]\n", $config->warnings[0]);
        $this->assertStringContainsString('plain text `ADMIN_TOKEN`', $config->warnings[1]);
        $this->assertStringContainsString('Secure Note size limit is increased', $config->warnings[2]);
    }

    /**
     * @param  array<string, string>  $env
     */
    private function load(array $env): Config
    {
        return Config::load(static fn (string $key): ?string => $env[$key] ?? null, $this->base);
    }
}
