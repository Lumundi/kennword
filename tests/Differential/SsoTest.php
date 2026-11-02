<?php

namespace Tests\Differential;

use GuzzleHttp\Client;
use RuntimeException;
use Tests\Attributes\Parity;

/**
 * SSO with OpenID Connect (src/sso.rs, the SSO parts of src/api/identity.rs)
 * on the pair of servers that log in at the fake provider of
 * .github/scripts/fake-services.php (VW_SSO_*). The test plays the browser:
 * it starts at /identity/connect/authorize, logs in at the provider and
 * comes back through /identity/connect/oidc-signin with the binding cookie.
 */
class SsoTest extends DifferentialTestCase
{
    private const string VERIFIER = 'differential-sso-verifier-0123456789-abcdefghijklmnopqrstuvwxyz';

    private const string DEVICE = '5d6e7f80-91a2-4b3c-8d4e-5f6a7b8c9d0e';

    #[Parity('route:GET /identity/sso/prevalidate')]
    #[Parity('route:GET /identity/connect/authorize')]
    #[Parity('route:GET /identity/connect/oidc-signin*')]
    #[Parity('route:POST /api/organizations/domain/sso/verified')]
    #[Parity('route:GET /api/organizations/{identifier}/auto-enroll-status')]
    #[Parity('config:SSO_ENABLED')]
    #[Parity('config:SSO_AUTHORITY')]
    #[Parity('config:SSO_CLIENT_ID')]
    #[Parity('config:SSO_CLIENT_SECRET')]
    #[Parity('config:SSO_SCOPES')]
    #[Parity('config:SSO_PKCE')]
    #[Parity('config:SSO_CALLBACK_PATH')]
    public function test_sign_up_log_in_and_refresh(): void
    {
        $this->assertSameSsoFlows(function (Server $server): array {
            $steps = [];
            $steps['prevalidate'] = $server->send('GET', '/identity/sso/prevalidate');
            $steps['verified domains'] = $server->send('POST', '/api/organizations/domain/sso/verified');

            $code = self::ssoCode($server, $steps, 'sign up', ['email' => 'sso-alice@example.com', 'name' => 'Alice']);
            $steps['sign up login'] = $login = self::login($server, $code);
            $auth = ['Authorization' => 'Bearer '.$login->jsonString('access_token'), 'Accept' => 'application/json'];
            $steps['profile'] = $server->send('GET', '/api/accounts/profile', $auth);
            $steps['auto enroll status'] = $server->send('GET', '/api/organizations/00000000-01DC-01DC-01DC-000000000000/auto-enroll-status', $auth);
            $steps['auto enroll status of nothing'] = $server->send('GET', '/api/organizations/nothing/auto-enroll-status', $auth);
            $steps['code again'] = self::login($server, $code);

            $steps['refresh'] = $server->form('/identity/connect/token', ['grant_type' => 'refresh_token', 'client_id' => 'web',
                'refresh_token' => $login->jsonString('refresh_token')]);
            $steps['set password'] = $server->json('POST', '/api/accounts/set-password', ['kdf' => 0, 'kdfIterations' => 600000,
                'key' => '2.user-key', 'keys' => ['encryptedPrivateKey' => '2.private', 'publicKey' => 'public-key'],
                'masterPasswordHash' => 'sso-hash', 'masterPasswordHint' => null, 'orgIdentifier' => '00000000-01DC-01DC-01DC-000000000000'], $auth);

            $code = self::ssoCode($server, $steps, 'log in again', ['email' => 'sso-alice@example.com']);
            $steps['log in again login'] = self::login($server, $code);

            return $steps;
        });
    }

    public function test_refused_logins(): void
    {
        $this->assertSameSsoFlows(function (Server $server): array {
            $steps = [];
            $authorize = ['client_id' => 'web', 'redirect_uri' => 'https://example.com', 'state' => 'refused-state',
                'code_challenge' => self::challenge(), 'code_challenge_method' => 'S256'];
            $steps['plain challenge'] = $server->send('GET', '/identity/connect/authorize?'.http_build_query([...$authorize, 'code_challenge_method' => 'plain']));
            $steps['unknown client'] = $server->send('GET', '/identity/connect/authorize?'.http_build_query([...$authorize, 'client_id' => 'tv']));
            $steps['cli elsewhere'] = $server->send('GET', '/identity/connect/authorize?'.http_build_query([...$authorize, 'client_id' => 'cli']));
            $steps['no state'] = $server->send('GET', '/identity/connect/authorize?'.http_build_query(array_diff_key($authorize, ['state' => true])));

            $steps['back with a broken state'] = $server->send('GET', '/identity/connect/oidc-signin?code=abc&state=%25%25');
            $steps['back with an unknown state'] = $server->send('GET', '/identity/connect/oidc-signin?code=abc&state='.base64_encode('nobody'));
            $steps['back without anything'] = $server->send('GET', '/identity/connect/oidc-signin?state='.base64_encode('nobody'));

            $code = self::ssoCode($server, $steps, 'wrong verifier', ['email' => 'sso-bob@example.com']);
            $steps['wrong verifier login'] = self::login($server, $code, verifier: str_repeat('x', 64));

            $code = self::ssoCode($server, $steps, 'denied', ['deny' => '1']);
            $steps['denied login'] = self::login($server, $code);
            // Vaultwarden 6ed6921c: the provider's error is escaped.
            $code = self::ssoCode($server, $steps, 'denied with quotes', ['deny' => '1', 'deny_description' => "The user's \"no\"\n"]);
            $steps['denied with quotes login'] = self::login($server, $code);

            $code = self::ssoCode($server, $steps, 'unverified', ['email' => 'sso-carol@example.com', 'verified' => 'false']);
            $steps['unverified login'] = self::login($server, $code);
            $code = self::ssoCode($server, $steps, 'unknown verification', ['email' => 'sso-carol@example.com', 'verified' => 'unknown']);
            $steps['unknown verification login'] = self::login($server, $code);

            // A user with a master password and the same address is linked.
            LoginTest::register($server, 'sso-dave@example.com');
            $code = self::ssoCode($server, $steps, 'existing user', ['email' => 'sso-dave@example.com']);
            $steps['existing user login'] = self::login($server, $code);
            // Another identity with that address is refused.
            $code = self::ssoCode($server, $steps, 'second identity', ['email' => 'sso-dave@example.com', 'sub' => 'other-sub']);
            $steps['second identity login'] = self::login($server, $code);

            $steps['without the binding cookie'] = self::ssoCode($server, $steps, 'no cookie', ['email' => 'sso-erin@example.com'], cookie: false);

            return $steps;
        });
    }

    /**
     * @param  callable(Server): array<string, Exchange>  $flow
     */
    private function assertSameSsoFlows(callable $flow): void
    {
        $this->assertSameFlowsOn((string) getenv('VW_SSO_REFERENCE_URL'), (string) getenv('VW_SSO_SUBJECT_URL'), $flow);
    }

    /**
     * Authorize, log in at the provider as the given user and come back: the
     * code the client then has. The answers go into the steps, with the
     * random code and nonce blanked out.
     *
     * @param  array<string, Exchange>  $steps
     * @param  array<string, string>  $user  The provider's test parameters
     * @return ($cookie is true ? string : Exchange)
     */
    private static function ssoCode(Server $server, array &$steps, string $name, array $user, bool $cookie = true): string|Exchange
    {
        $state = str_replace(' ', '-', $name).'-state';
        $authorize = $server->send('GET', '/identity/connect/authorize?'.http_build_query(['client_id' => 'web', 'redirect_uri' => 'https://example.com/redirect',
            'response_type' => 'code', 'scope' => 'api offline_access', 'state' => $state, 'code_challenge' => self::challenge(), 'code_challenge_method' => 'S256']));
        $steps["{$name} authorize"] = self::blanked($authorize);
        $location = $authorize->header('location') ?? throw new RuntimeException("No redirect to the provider: {$authorize->status} {$authorize->body}");
        preg_match('/VW_SSO_BINDING=([^;]+)/', (string) $authorize->header('set-cookie'), $binding);

        $client = new Client(['verify' => (string) getenv('VW_SERVICES_CA'), 'allow_redirects' => false, 'http_errors' => false, 'timeout' => 10]);
        $back = $client->get($location.'&'.http_build_query($user))->getHeaderLine('Location');
        $query = (string) parse_url($back, PHP_URL_QUERY);

        $signin = $server->send('GET', '/identity/connect/oidc-signin?'.$query, $cookie ? ['Cookie' => 'VW_SSO_BINDING='.($binding[1] ?? '')] : []);
        if (! $cookie) {
            return $signin;
        }
        $steps["{$name} back from the provider"] = self::blanked($signin);
        parse_str((string) parse_url((string) $signin->header('location'), PHP_URL_QUERY), $params);

        return is_string($params['code'] ?? null) ? $params['code'] : throw new RuntimeException("No code for the client: {$signin->status} {$signin->body}");
    }

    private static function login(Server $server, string $code, string $verifier = self::VERIFIER): Exchange
    {
        return $server->form('/identity/connect/token', ['grant_type' => 'authorization_code', 'code' => $code, 'code_verifier' => $verifier,
            'client_id' => 'web', 'scope' => 'api offline_access', 'device_identifier' => self::DEVICE, 'device_name' => 'firefox', 'device_type' => '10']);
    }

    private static function challenge(): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '=');
    }

    /**
     * The redirect without the random code and nonce.
     */
    private static function blanked(Exchange $exchange): Exchange
    {
        $location = $exchange->header('location');
        if ($location === null) {
            return $exchange;
        }
        $location = (string) preg_replace(['/([?&]code=)[0-9a-f]{32}/', '/([?&]nonce=)[A-Za-z0-9_-]{22}/'], ['$1<code>', '$1<nonce>'], $location);

        return new Exchange($exchange->status, ['location' => $location] + $exchange->headers, $exchange->body);
    }
}
