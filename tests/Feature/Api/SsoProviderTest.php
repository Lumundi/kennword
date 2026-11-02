<?php

namespace Tests\Feature\Api;

use App\Models\SsoUser;
use App\Models\User;
use Illuminate\Support\Facades\Log;
use Illuminate\Testing\TestResponse;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\UsesFakeServices;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\TestCase;

/**
 * SSO logins at the fake OpenID provider of .github/scripts/fake-services.php,
 * through authorize, the provider, the callback and the token endpoint.
 */
class SsoProviderTest extends TestCase
{
    use UsesFakeServices {
        setUpBeforeClass as private startServices;
    }
    use UsesVaultwardenDatabase;

    private const string SECRET = 'sso-provider-secret';

    private const string VERIFIER = 'a-verifier-of-the-client-that-is-long-enough-for-pkce-0123456789';

    public static function setUpBeforeClass(): void
    {
        // The provider reads its client's secret from the environment it starts with.
        putenv('SSO_CLIENT_SECRET='.self::SECRET);
        self::startServices();
    }

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000', 'SSL_CERT_FILE' => self::$servicesFolder.'/ca.pem', 'SSO_ENABLED' => 'true',
            'SSO_AUTHORITY' => 'https://'.self::$servicesHost.'/oidc', 'SSO_CLIENT_ID' => 'vaultwarden', 'SSO_CLIENT_SECRET' => self::SECRET,
            'SSO_SCOPES' => 'email profile offline_access', 'SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION' => 'true'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');
    }

    /**
     * Vaultwarden's openidconnect takes booleans only: a provider that sends
     * "false" as a string must not pass for one whose verification is
     * unknown, which SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION lets link an
     * existing account with that address.
     */
    public function test_a_verification_status_that_is_not_a_boolean_is_refused(): void
    {
        $victim = User::new('victim@example.com');
        $victim->setPassword('hash', 'user-key', false, null);
        $victim->private_key = '2.private';
        $victim->save();

        foreach (['text-false', 'text-true'] as $verified) {
            $this->login($this->ssoCode(['email' => 'victim@example.com', 'verified' => $verified]))
                ->assertStatus(400)->assertJsonPath('message', 'Failed to contact token endpoint: Parse(..)');
        }
        $this->assertNull((SsoUser::findByMail('victim@example.com') ?? [null, null])[1]);

        // Without a status at all, the setting allows the link.
        $this->login($this->ssoCode(['email' => 'victim@example.com', 'verified' => 'unknown']))->assertStatus(200);
        $this->assertNotNull((SsoUser::findByMail('victim@example.com') ?? [null, null])[1]);
    }

    /**
     * Vaultwarden be5d3ad9 and 6ed6921c: only SSO_DEBUG_TOKENS logs the
     * provider's tokens, and its errors are escaped.
     */
    public function test_the_log_keeps_the_tokens_and_the_errors_are_escaped(): void
    {
        $log = Log::spy();
        $this->login($this->ssoCode(['email' => 'logged@example.com', 'name' => 'logged']))->assertStatus(200);
        $identifier = 'https://'.self::$servicesHost.'/oidc/sub-'.substr(sha1('logged@example.com'), 0, 12);
        $log->shouldHaveReceived('debug')->with("Authenticated user {$identifier}");

        $this->changeVaultwardenEnvironment(['SSO_DEBUG_TOKENS' => 'true']);
        $this->login($this->ssoCode(['email' => 'logged@example.com', 'name' => 'logged']))->assertStatus(200);
        $log->shouldHaveReceived('debug')->withArgs(static fn (string $message): bool => str_starts_with($message, 'Authenticated user OIDCAuthenticatedUser { refresh_token: Some("')
            && str_ends_with($message, "\", expires_in: Some(3600s), identifier: OIDCIdentifier(\"{$identifier}\"), email: \"logged@example.com\", "
                .'email_verified: Some(true), user_name: Some("logged") }'));

        $this->login($this->ssoCode(['deny' => '1', 'deny_description' => "The user's \"no\"\n"]))
            ->assertStatus(400)->assertJsonPath('message', 'SSO authorization failed: access_denied, The user\\\'s \\"no\\"\\n');
    }

    /**
     * Authorize, log in at the provider as the given user and come back: the
     * code the client then has.
     *
     * @param  array<string, string>  $user  The provider's test parameters
     */
    private function ssoCode(array $user): string
    {
        $authorize = $this->get('/identity/connect/authorize?'.http_build_query(['client_id' => 'web', 'redirect_uri' => 'https://example.com/redirect',
            'response_type' => 'code', 'scope' => 'api offline_access', 'state' => 'state-'.bin2hex(random_bytes(4)),
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '='), 'code_challenge_method' => 'S256']))
            ->assertStatus(307);
        $binding = $authorize->getCookie('VW_SSO_BINDING', decrypt: false)?->getValue() ?? throw new RuntimeException('No binding cookie.');

        $context = stream_context_create(['http' => ['follow_location' => 0, 'ignore_errors' => true], 'ssl' => ['cafile' => self::$servicesFolder.'/ca.pem']]);
        file_get_contents((string) $authorize->headers->get('Location').'&'.http_build_query($user), false, $context);
        $back = '';
        foreach (http_get_last_response_headers() ?? [] as $header) {
            if (stripos($header, 'Location:') === 0) {
                $back = trim(substr($header, strlen('Location:')));
            }
        }

        $signin = $this->withUnencryptedCookie('VW_SSO_BINDING', $binding)
            ->get('/identity/connect/oidc-signin?'.parse_url($back, PHP_URL_QUERY))->assertStatus(307);
        parse_str((string) parse_url((string) $signin->headers->get('Location'), PHP_URL_QUERY), $params);

        return is_string($params['code'] ?? null) ? $params['code'] : throw new RuntimeException('No code for the client.');
    }

    /**
     * @return TestResponse<Response>
     */
    private function login(string $code): TestResponse
    {
        return $this->call('POST', '/identity/connect/token', [], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], http_build_query([
            'grant_type' => 'authorization_code', 'code' => $code, 'code_verifier' => self::VERIFIER, 'client_id' => 'web',
            'scope' => 'api offline_access', 'device_identifier' => 'b4e5c4a8-8c6b-4b1e-9d36-5a6f1f2f3f4f', 'device_name' => 'firefox', 'device_type' => '10']));
    }
}
