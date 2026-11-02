<?php

namespace App\Config;

/**
 * Client feature flags that EXPERIMENTAL_CLIENT_FEATURE_FLAGS may enable
 * (SUPPORTED_FEATURE_FLAGS in src/config.rs).
 */
final class FeatureFlags
{
    public const array SUPPORTED = [
        // Auth Team
        'pm-5594-safari-account-switching',
        'pm-32413-multi-client-password-management',
        // Autofill Team
        'undetermined-cipher-scenario-logic',
        'enable-basic-auth-response',
        'fill-assist-targeting-rules',
        'ssh-agent-v2',
        'windows-desktop-autotype',
        'windows-desktop-autotype-ga',
        // Key Management Team
        'biometrics-sdk-ipc',
        'windows-native-credential-sync',
        // Mobile Team
        'pm-34171-card-scanner',
        // Platform Team
        'pm-30529-webauthn-related-origins',
        // Vault Team
        'pm-32009-new-item-types',
    ];

    /**
     * parse_experimental_client_feature_flags
     *
     * @param  'all'|'valid'|'invalid'  $filter
     * @return array<string, true>
     */
    public static function parse(string $flags, string $filter = 'all'): array
    {
        $parsed = [];
        foreach (explode(',', $flags) as $flag) {
            $flag = trim($flag);
            $supported = in_array($flag, self::SUPPORTED, true);
            if ($flag !== '' && ($filter === 'all' || ($filter === 'valid') === $supported)) {
                $parsed[$flag] = true;
            }
        }

        return $parsed;
    }
}
