<?php

namespace App\Config;

use App\Support\PrivateFile;
use InvalidArgumentException;

/**
 * Vaultwarden's configuration (CONFIG in src/config.rs): environment variables,
 * overridden by the config.json the admin panel writes, completed with the
 * defaults of every setting.
 *
 * Relative paths are relative to the working directory in Vaultwarden; here
 * they are relative to the application's base path (see path()).
 */
final class Config
{
    /**
     * @param  array<string, string|int|bool|null>  $values  Every setting, keyed by name
     * @param  list<string>  $overrides  Environment variables overridden by config.json
     * @param  list<string>  $warnings  What Vaultwarden prints at startup without refusing to start
     */
    public function __construct(
        private readonly array $values,
        private readonly string $basePath,
        public readonly ConfigBuilder $env = new ConfigBuilder,
        public readonly ConfigBuilder $file = new ConfigBuilder,
        public readonly array $overrides = [],
        public readonly ConfigFileStatus $fileStatus = ConfigFileStatus::NotFound,
        public readonly string $configFile = 'data/config.json',
        public private(set) array $warnings = [],
    ) {}

    /**
     * Load and validate the configuration like Config::load.
     *
     * @param  callable(string): ?string  $env  Reads an environment variable
     *
     * @throws ConfigException
     */
    public static function load(callable $env, string $basePath, bool $validate = true): self
    {
        $fromEnv = ConfigBuilder::fromEnv($env);
        $configFile = ConfigBuilder::envValue($env, 'CONFIG_FILE')
            ?? Settings::joinPath(ConfigBuilder::envValue($env, 'DATA_FOLDER') ?? 'data', 'config.json');

        $warnings = [];
        foreach ($fromEnv->invalid as $key) {
            $warnings[] = "`{$key}` contains an invalid value for its type and is ignored, the default is used instead.";
        }

        try {
            $fromFile = ConfigBuilder::fromFile(self::absolute($configFile, $basePath));
            $status = $fromFile === null ? ConfigFileStatus::NotFound : ConfigFileStatus::Loaded;
        } catch (ConfigException $exception) {
            // An invalid file is ignored as a whole.
            $warnings[] = "Failed to load configuration from `{$configFile}`: {$exception->getMessage()}";
            $fromFile = null;
            $status = ConfigFileStatus::Error;
        }
        $fromFile ??= new ConfigBuilder;

        $overrides = [];
        $merged = $fromEnv->merge($fromFile, $overrides);
        if ($overrides !== []) {
            $warnings[] = 'The following environment variables are being overridden by the config.json file. '
                .'Please use the admin panel to make changes to them: '.implode(', ', $overrides);
        }
        if (isset($merged->values['smtp_ssl']) || isset($merged->values['smtp_explicit_tls'])) {
            $warnings[] = '`SMTP_SSL` or `SMTP_EXPLICIT_TLS` is set. Please use `SMTP_SECURITY` instead.';
        }

        $config = new self($merged->build(), $basePath, $fromEnv, $fromFile, $overrides, $status, $configFile, $warnings);
        if ($validate) {
            $config->warnings = [...$warnings, ...ConfigValidator::validate($config)];
        }

        return $config;
    }

    public function get(string $name): string|int|bool|null
    {
        if (! array_key_exists($name, $this->values)) {
            throw new InvalidArgumentException("Unknown setting [{$name}].");
        }

        return $this->values[$name];
    }

    public function string(string $name): string
    {
        $value = $this->get($name);

        return is_string($value) ? $value : throw new InvalidArgumentException("Setting [{$name}] is not a string.");
    }

    public function optionalString(string $name): ?string
    {
        $value = $this->get($name);

        return $value === null || is_string($value) ? $value : throw new InvalidArgumentException("Setting [{$name}] is not a string.");
    }

    public function bool(string $name): bool
    {
        $value = $this->get($name);

        return is_bool($value) ? $value : throw new InvalidArgumentException("Setting [{$name}] is not a boolean.");
    }

    public function int(string $name): int
    {
        $value = $this->get($name);

        return is_int($value) ? $value : throw new InvalidArgumentException("Setting [{$name}] is not an integer.");
    }

    public function optionalInt(string $name): ?int
    {
        $value = $this->get($name);

        return $value === null || is_int($value) ? $value : throw new InvalidArgumentException("Setting [{$name}] is not an integer.");
    }

    /**
     * A path setting, made absolute against the base path.
     */
    public function path(string $name): string
    {
        return self::absolute($this->string($name), $this->basePath);
    }

    public function absolutePath(string $path): string
    {
        return self::absolute($path, $this->basePath);
    }

    /**
     * Whether the domain of an email address is in SIGNUPS_DOMAINS_WHITELIST, or no whitelist is set.
     */
    public function isEmailDomainAllowed(string $email): bool
    {
        $at = strrpos($email, '@');
        if ($at === false || $at === 0 || $at === strlen($email) - 1) {
            return false;
        }

        $domain = strtolower(substr($email, $at + 1));
        $whitelist = $this->string('signups_domains_whitelist');

        return $whitelist === '' || in_array($domain, array_map(trim(...), explode(',', $whitelist)), true);
    }

    /**
     * The whitelist overrides SIGNUPS_ALLOWED.
     */
    public function isSignupAllowed(string $email): bool
    {
        return $this->string('signups_domains_whitelist') === ''
            ? $this->bool('signups_allowed')
            : $this->isEmailDomainAllowed($email);
    }

    public function isSsoSignupAllowed(string $email): bool
    {
        return $this->string('signups_domains_whitelist') === ''
            ? $this->bool('sso_signups_allowed')
            : $this->isEmailDomainAllowed($email);
    }

    /**
     * Whether the registration link should be hidden.
     */
    public function isSignupDisabled(): bool
    {
        return (! $this->bool('signups_allowed')
                && $this->string('signups_domains_whitelist') === ''
                && ($this->mailEnabled() || ! $this->bool('invitations_allowed')))
            || ($this->bool('sso_enabled') && $this->bool('sso_only'));
    }

    public function isOrgCreationAllowed(string $email): bool
    {
        $users = $this->string('org_creation_users');

        return match ($users) {
            '', 'all' => true,
            'none' => false,
            default => in_array(strtolower($email), array_map(trim(...), explode(',', $users)), true),
        };
    }

    /**
     * The file of the RSA key that signs the login tokens.
     */
    public function privateRsaKey(): string
    {
        return $this->string('rsa_key_filename').'.pem';
    }

    public function mailEnabled(): bool
    {
        return $this->bool('_enable_smtp') && ($this->optionalString('smtp_host') !== null || $this->bool('use_sendmail'));
    }

    public function isWebauthn2faSupported(): bool
    {
        return Url::domain($this->string('domain')) !== null;
    }

    public function isAdminTokenSet(): bool
    {
        return trim($this->optionalString('admin_token') ?? '') !== '';
    }

    /**
     * Config::prepare_json: every group of settings with its documentation,
     * and each setting with its value, its default (the environment's value
     * or the built-in default) and whether config.json overrides it.
     *
     * @return list<array{group: string, grouptoggle: string, groupdoc: string, elements: list<array<string, mixed>>}>
     */
    public function prepareJson(): array
    {
        $defaults = $this->env->build();
        $elements = [];
        foreach (Settings::all() as $name => $setting) {
            [$docName, $description] = SettingDocs::SETTINGS[$name];
            // ElementData
            $elements[$setting->group][] = [
                'editable' => $setting->editable,
                'name' => $name,
                'value' => $this->values[$name],
                'default' => $defaults[$name],
                'type' => match ($setting->type) {
                    SettingType::Pass => 'password',
                    SettingType::String => 'text',
                    SettingType::Bool => 'checkbox',
                    default => 'number',
                },
                'doc' => ['name' => $docName, 'description' => $description],
                'overridden' => in_array(strtoupper($name), $this->overrides, true),
            ];
        }

        // GroupData
        $groups = [];
        foreach (SettingDocs::GROUPS as $group => [$toggle, $doc]) {
            $groups[] = ['group' => $group, 'grouptoggle' => $toggle, 'groupdoc' => $doc, 'elements' => $elements[$group] ?? []];
        }

        return $groups;
    }

    /**
     * Config::get_support_json: every setting, with passwords replaced by
     * "***" and the values that could identify the server masked.
     *
     * @return array<string, string|int|bool|null> Sorted by name
     */
    public function supportJson(): array
    {
        $json = [];
        foreach (Settings::all() as $name => $setting) {
            $value = $this->values[$name];
            if ($setting->type === SettingType::Pass) {
                $value = $setting->action === 'option' && $value === null ? null : '***';
            } elseif (is_string($value) && in_array($name, self::PRIVACY_CONFIG, true)) {
                $value = self::privacyMask($value);
            }
            $json[$name] = $value;
        }
        ksort($json, SORT_STRING);

        return $json;
    }

    /**
     * Config::update_config: keep the settings that may be edited, check the
     * result like at startup (more strictly) and write config.json. Values
     * that equal their defaults are written too.
     *
     * @return self The configuration from now on
     *
     * @throws ConfigException
     */
    public function updateConfig(ConfigBuilder $other): self
    {
        $builder = $other->withoutNonEditable();

        $overrides = [];
        $config = new self($this->env->merge($builder, $overrides)->build(), $this->basePath, $this->env, $builder,
            $overrides, ConfigFileStatus::Loaded, $this->configFile);
        ConfigValidator::validate($config, onUpdate: true);

        $file = $this->absolutePath($this->configFile);
        if (! is_dir(dirname($file))) {
            @mkdir(dirname($file), 0777, true);
        }
        // Every request reads the file, so it is replaced at once: one being written would read as empty and
        // leave that request with the environment alone.
        // It holds the admin token and other secrets: a new file is its owner's only, an existing one keeps its mode.
        $temporary = $file.'.'.bin2hex(random_bytes(6)).'.tmp';
        $mode = @fileperms($file);
        if (! PrivateFile::create($temporary, $builder->toJson())
            || ($mode !== false && ! @chmod($temporary, $mode & 0777))
            || ! @rename($temporary, $file)) {
            @unlink($temporary);
            throw new ConfigException("Failed to write `{$this->configFile}`.");
        }

        return $config;
    }

    /**
     * Config::delete_user_config: remove config.json; a missing file is fine.
     *
     * @return self The configuration from now on: the environment and the defaults
     *
     * @throws ConfigException
     */
    public function deleteUserConfig(): self
    {
        $file = $this->absolutePath($this->configFile);
        if (is_file($file) && ! @unlink($file)) {
            throw new ConfigException("Failed to delete `{$this->configFile}`.");
        }

        return new self($this->env->build(), $this->basePath, $this->env, new ConfigBuilder, [], ConfigFileStatus::NotFound, $this->configFile);
    }

    /**
     * The settings whose string values get_support_json masks. Passwords are always hidden.
     */
    private const array PRIVACY_CONFIG = [
        'allowed_connect_src',
        'allowed_iframe_ancestors',
        'database_url',
        'domain_origin',
        'domain_path',
        'domain',
        'duo_ikey',
        'duo_host',
        'helo_name',
        'org_creation_users',
        'signups_domains_whitelist',
        '_smtp_img_src',
        'smtp_from_name',
        'smtp_from',
        'smtp_host',
        'smtp_username',
        'sso_authority',
        'sso_callback_path',
        'sso_client_id',
        'yubico_client_id',
        'yubico_server',
    ];

    /**
     * Every character becomes `*`, except commas, a colon among the first 11
     * characters and slashes among the first 13 after it, so that a URL keeps
     * its scheme.
     */
    private static function privacyMask(string $value): string
    {
        $masked = '';
        $colon = false;
        foreach (mb_str_split($value, 1, 'UTF-8') as $index => $char) {
            $position = $index + 1;
            if ($char === ':' && $position <= 11) {
                $colon = true;
                $masked .= $char;
            } elseif (($char === '/' && $position <= 13 && $colon) || $char === ',') {
                $masked .= $char;
            } else {
                $masked .= '*';
            }
        }

        return $masked;
    }

    private static function absolute(string $path, string $basePath): string
    {
        return $path === '' || str_starts_with($path, '/') ? $path : rtrim($basePath, '/').'/'.$path;
    }
}
