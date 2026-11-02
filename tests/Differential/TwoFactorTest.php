<?php

namespace Tests\Differential;

use App\Http\Controllers\TwoFactor\AuthenticatorController;
use App\Support\Base32;
use GuzzleHttp\Client;
use Tests\Attributes\Parity;
use Tests\Support\SoftwareAuthenticator;

/**
 * Two-factor methods and the logins that need them. The test computes the
 * authenticator codes itself and reads the mailed ones from the SMTP sinks.
 */
class TwoFactorTest extends DifferentialTestCase
{
    #[Parity('route:GET /api/two-factor')]
    #[Parity('route:GET /api/two-factor/get-device-verification-settings')]
    #[Parity('route:POST /api/two-factor/get-authenticator')]
    #[Parity('route:POST /api/two-factor/authenticator')]
    #[Parity('route:PUT /api/two-factor/authenticator')]
    #[Parity('route:DELETE /api/two-factor/authenticator')]
    public function test_authenticator_and_remembered_devices(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$auth, $userId] = CipherTest::session($server, '2fa-totp@example.com');
            $login = LoginTest::loginFields('2fa-totp@example.com');
            $password = ['masterPasswordHash' => 'client-hash'];
            $steps = [];

            $steps['methods'] = $server->send('GET', '/api/two-factor', $auth);
            $steps['device verification settings'] = $server->send('GET', '/api/two-factor/get-device-verification-settings', $auth);
            $steps['get authenticator with a wrong password'] = $server->json('POST', '/api/two-factor/get-authenticator', ['masterPasswordHash' => 'wrong'], $auth);
            $steps['get authenticator without validation'] = $server->json('POST', '/api/two-factor/get-authenticator', [], $auth);
            $steps['get authenticator'] = $setup = $server->json('POST', '/api/two-factor/get-authenticator', $password, $auth);
            $key = $setup->jsonString('authenticator.key');
            $secret = Base32::decode($key) ?? '';
            $activate = ['key' => $key, 'userVerificationToken' => $setup->jsonString('userVerificationToken')];
            $code = AuthenticatorController::totp($secret, time());

            $steps['activate with a wrong code'] = $server->json('POST', '/api/two-factor/authenticator', [...$activate, 'token' => self::otherCode($secret)], $auth);
            $steps['activate with another key'] = $server->json('POST', '/api/two-factor/authenticator', [...$activate, 'key' => 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', 'token' => $code], $auth);
            $steps['activate with a bad token'] = $server->json('POST', '/api/two-factor/authenticator', [...$activate, 'userVerificationToken' => 'nope', 'token' => $code], $auth);
            $steps['activate without code'] = $server->json('POST', '/api/two-factor/authenticator', $activate, $auth);
            $steps['activate a short key'] = $server->json('POST', '/api/two-factor/authenticator', ['key' => 'AAAAAAAA', 'token' => $code,
                'userVerificationToken' => $this->verificationToken($userId, ['authenticator_key' => 'AAAAAAAA'])], $auth);
            $steps['activate a key without padding'] = $server->json('POST', '/api/two-factor/authenticator', ['key' => 'AAAA', 'token' => $code,
                'userVerificationToken' => $this->verificationToken($userId, ['authenticator_key' => 'AAAA'])], $auth);
            $steps['activate a key that is no base32'] = $server->json('POST', '/api/two-factor/authenticator', ['key' => 'A1', 'token' => $code,
                'userVerificationToken' => $this->verificationToken($userId, ['authenticator_key' => 'A1'])], $auth);
            $steps['activate with another method\'s token'] = $server->json('POST', '/api/two-factor/authenticator', [...$activate, 'token' => $code,
                'userVerificationToken' => $this->verificationToken($userId, ['email' => null])], $auth);
            // A number works as well, unless it loses a leading zero.
            $steps['activate'] = $server->json('POST', '/api/two-factor/authenticator', [...$activate, 'token' => $code[0] === '0' ? $code : (int) $code], $auth);
            $steps['activate again with the code'] = $server->json('PUT', '/api/two-factor/authenticator', [...$activate, 'token' => $code], $auth);
            $steps['methods with the authenticator'] = $server->send('GET', '/api/two-factor', $auth);
            $steps['profile'] = $server->send('GET', '/api/accounts/profile', $auth);

            $steps['login without code'] = $server->form('/identity/connect/token', $login);
            $steps['login with a method not set up'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '1', 'two_factor_token' => '123456']);
            $steps['login with a blank code'] = $server->form('/identity/connect/token', [...$login, 'two_factor_token' => ' ']);
            $steps['login with letters'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '0', 'two_factor_token' => 'abc']);
            $steps['login with a provider that is no number'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => 'x', 'two_factor_token' => 'abc']);
            $steps['login with the used code'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '0', 'two_factor_token' => $code]);
            $steps['login remembering the device'] = $remembered = $server->form('/identity/connect/token', [...$login, 'twofactorprovider' => '0',
                'twofactortoken' => AuthenticatorController::totp($secret, time() + 30), 'twofactorremember' => '1']);
            $rememberToken = $remembered->jsonString('TwoFactorToken');
            $steps['login with the remember token'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '5', 'two_factor_token' => $rememberToken]);
            $steps['login with a wrong remember token'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '5', 'two_factor_token' => 'nope']);
            $steps['login with the dropped remember token'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '5', 'two_factor_token' => $rememberToken]);

            $steps['get authenticator again'] = $enabled = $server->json('POST', '/api/two-factor/get-authenticator', $password, $auth);
            $steps['disable with the old token'] = $server->json('DELETE', '/api/two-factor/authenticator', $activate, $auth);
            $steps['disable with another key'] = $server->json('DELETE', '/api/two-factor/authenticator', ['key' => 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
                'userVerificationToken' => $enabled->jsonString('userVerificationToken')], $auth);
            $steps['disable'] = $server->json('DELETE', '/api/two-factor/authenticator', [...$activate, 'userVerificationToken' => $enabled->jsonString('userVerificationToken')], $auth);
            $steps['methods at last'] = $server->send('GET', '/api/two-factor', $auth);
            $steps['login at last'] = $server->form('/identity/connect/token', $login);

            // Without mail neither codes by mail nor protected actions work.
            $steps['send email'] = $server->json('POST', '/api/two-factor/send-email', ['email' => '2fa-totp@example.com',
                'userVerificationToken' => $server->json('POST', '/api/two-factor/get-email', $password, $auth)->jsonString('userVerificationToken')], $auth);
            $steps['send email login'] = $server->json('POST', '/api/two-factor/send-email-login', ['email' => '2fa-totp@example.com', 'masterPasswordHash' => 'client-hash']);
            $steps['request otp'] = $server->send('POST', '/api/accounts/request-otp', $auth);
            $steps['get yubikey without credentials'] = $server->json('POST', '/api/two-factor/get-yubikey', $password, $auth);
            $steps['get duo without global keys'] = $server->json('POST', '/api/two-factor/get-duo', $password, $auth);
            $steps['verify otp'] = $server->json('POST', '/api/accounts/verify-otp', ['otp' => '123456'], $auth);

            return $steps;
        });
    }

    #[Parity('route:POST /api/two-factor/get-email')]
    #[Parity('route:POST /api/two-factor/send-email')]
    #[Parity('route:PUT /api/two-factor/email')]
    #[Parity('route:DELETE /api/two-factor/email')]
    #[Parity('route:POST /api/two-factor/send-email-login')]
    #[Parity('route:POST /api/two-factor/get-recover')]
    #[Parity('template:email/twofactor_email*')]
    #[Parity('template:email/recover_twofactor*')]
    #[Parity('config:_ENABLE_EMAIL_2FA')]
    public function test_email_codes_and_the_recovery_code(): void
    {
        $this->assertSameMailFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, '2fa-mail@example.com');
            $login = LoginTest::loginFields('2fa-mail@example.com');
            $password = ['masterPasswordHash' => 'client-hash'];
            $steps = [];

            $steps['get email'] = $setup = $server->json('POST', '/api/two-factor/get-email', $password, $auth);
            $verification = $setup->jsonString('userVerificationToken');
            $address = ['email' => '2fa-other@example.com', 'userVerificationToken' => $verification];
            $steps['send email with a bad token'] = $server->json('POST', '/api/two-factor/send-email', [...$address, 'userVerificationToken' => 'nope'], $auth);
            $steps['send email'] = $server->json('POST', '/api/two-factor/send-email', $address, $auth);
            [$steps['code mail'], $code] = self::codeMail($server, '2fa-other@example.com');
            $steps['activate with a wrong code'] = $server->json('PUT', '/api/two-factor/email', [...$address, 'token' => 'nope'], $auth);
            $steps['activate without code'] = $server->json('PUT', '/api/two-factor/email', $address, $auth);
            // The address comes from the challenge, whatever the request names.
            $steps['activate naming another address'] = $server->json('PUT', '/api/two-factor/email', [...$address, 'email' => '2fa-mail@example.com', 'token' => $code], $auth);
            $steps['activate again'] = $server->json('PUT', '/api/two-factor/email', [...$address, 'token' => $code], $auth);
            $steps['get email again'] = $server->json('POST', '/api/two-factor/get-email', $password, $auth);
            $steps['methods'] = $server->send('GET', '/api/two-factor', $auth);

            $steps['login without code'] = $server->form('/identity/connect/token', $login);
            $steps['send login code with a wrong password'] = $server->json('POST', '/api/two-factor/send-email-login', ['email' => '2fa-mail@example.com', 'masterPasswordHash' => 'wrong']);
            $steps['send login code for an unknown user'] = $server->json('POST', '/api/two-factor/send-email-login', ['email' => '2fa-nobody@example.com', 'masterPasswordHash' => 'client-hash']);
            $steps['send login code without password'] = $server->json('POST', '/api/two-factor/send-email-login', ['email' => '2fa-mail@example.com']);
            $steps['send login code with a list'] = $server->json('POST', '/api/two-factor/send-email-login', []);
            $steps['send login code without anything'] = $server->send('POST', '/api/two-factor/send-email-login', ['Content-Type' => 'application/json'], '{}');
            $steps['send login code for an unknown device'] = $server->json('POST', '/api/two-factor/send-email-login', ['deviceIdentifier' => '6d1c5b2e-0000-4000-8000-000000000000']);
            $steps['send login code for the pending login'] = $server->json('POST', '/api/two-factor/send-email-login', ['DeviceIdentifier' => LoginTest::DEVICE]);
            [$steps['login code mail'], $code] = self::codeMail($server, '2fa-other@example.com');
            $steps['login with a wrong code'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '1', 'two_factor_token' => 'nope']);
            $steps['login'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '1', 'two_factor_token' => $code]);
            $steps['login with the used code'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '1', 'two_factor_token' => $code]);
            $steps['send login code with the password'] = $server->json('POST', '/api/two-factor/send-email-login', ['email' => '2fa-mail@example.com', 'masterPasswordHash' => 'client-hash']);
            [$steps['second login code mail']] = self::codeMail($server, '2fa-other@example.com');

            // Vaultwarden acb574b7: a login request stands in for the password once it is approved.
            $asking = ['Accept' => 'application/json', 'Device-Type' => '25'];
            $id = $server->json('POST', '/api/auth-requests', ['accessCode' => 'access-code', 'deviceIdentifier' => LoginTest::DEVICE, 'email' => '2fa-mail@example.com',
                'publicKey' => 'device-public-key', 'type' => 0], $asking)->jsonString('id');
            $byRequest = ['email' => '2fa-mail@example.com', 'authRequestId' => $id, 'authRequestAccessCode' => 'access-code'];
            $steps['send login code for an unapproved request'] = $server->json('POST', '/api/two-factor/send-email-login', $byRequest, $asking);
            $server->json('PUT', "/api/auth-requests/{$id}", ['deviceIdentifier' => LoginTest::DEVICE, 'key' => '4.key', 'masterPasswordHash' => null, 'requestApproved' => true], $auth);
            $steps['send login code without the access code'] = $server->json('POST', '/api/two-factor/send-email-login', [...$byRequest, 'authRequestAccessCode' => null], $asking);
            $steps['send login code with a wrong access code'] = $server->json('POST', '/api/two-factor/send-email-login', [...$byRequest, 'authRequestAccessCode' => 'nope'], $asking);
            $steps['send login code from another device type'] = $server->json('POST', '/api/two-factor/send-email-login', $byRequest, [...$asking, 'Device-Type' => '10']);
            $steps['send login code for an approved request'] = $server->json('POST', '/api/two-factor/send-email-login', $byRequest, $asking);
            [$steps['request login code mail']] = self::codeMail($server, '2fa-other@example.com');

            $steps['recovery code with a wrong password'] = $server->json('POST', '/api/two-factor/get-recover', ['masterPasswordHash' => 'wrong'], $auth);
            $steps['recovery code'] = $recover = $server->json('POST', '/api/two-factor/get-recover', $password, $auth);
            $steps['login with a wrong recovery code'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '8', 'two_factor_token' => 'nope']);
            $spaced = strtoupper(implode(' ', str_split($recover->jsonString('code'), 4)));
            $steps['login with the recovery code'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '8', 'two_factor_token' => $spaced]);
            $steps['recovery mail'] = $server->mail('2fa-mail@example.com')->exchange();
            $steps['methods after the recovery'] = $server->send('GET', '/api/two-factor', $auth);
            $steps['recovery code after the recovery'] = $server->json('POST', '/api/two-factor/get-recover', $password, $auth);
            $steps['login after the recovery'] = $server->form('/identity/connect/token', $login);

            // Set up again, then switched off.
            $setup = $server->json('POST', '/api/two-factor/get-email', $password, $auth);
            $server->json('POST', '/api/two-factor/send-email', ['email' => '2fa-mail@example.com', 'userVerificationToken' => $setup->jsonString('userVerificationToken')], $auth);
            [, $code] = self::codeMail($server, '2fa-mail@example.com');
            $server->json('PUT', '/api/two-factor/email', ['email' => '2fa-mail@example.com', 'token' => $code, 'userVerificationToken' => $setup->jsonString('userVerificationToken')], $auth);
            $steps['login code for the account address'] = $server->form('/identity/connect/token', $login);
            $enabled = $server->json('POST', '/api/two-factor/get-email', $password, $auth);
            $steps['disable with the old token'] = $server->json('DELETE', '/api/two-factor/email', ['userVerificationToken' => $verification], $auth);
            $steps['disable'] = $server->json('DELETE', '/api/two-factor/email', ['userVerificationToken' => $enabled->jsonString('userVerificationToken')], $auth);
            $steps['disable again'] = $server->json('DELETE', '/api/two-factor/email', ['userVerificationToken' => 'nope'], $auth);
            $steps['methods at last'] = $server->send('GET', '/api/two-factor', $auth);

            return $steps;
        });
    }

    #[Parity('route:POST /api/accounts/request-otp')]
    #[Parity('route:POST /api/accounts/verify-otp')]
    #[Parity('template:email/protected_action*')]
    public function test_protected_actions(): void
    {
        $this->assertSameMailFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, '2fa-otp@example.com');
            $steps = [];

            $steps['verify without a code'] = $server->json('POST', '/api/accounts/verify-otp', ['otp' => '123456'], $auth);
            $steps['request'] = $server->send('POST', '/api/accounts/request-otp', $auth);
            [$steps['mail'], $code] = self::codeMail($server, '2fa-otp@example.com');
            $again = $server->send('POST', '/api/accounts/request-otp', $auth);
            $steps['request again'] = $again->withBody((string) preg_replace('/wait \d+ seconds/', 'wait <n> seconds', $again->body));
            $steps['verify with a wrong code'] = $server->json('POST', '/api/accounts/verify-otp', ['otp' => 'nope'], $auth);
            $steps['verify without otp'] = $server->json('POST', '/api/accounts/verify-otp', [], $auth);
            // The code also stands in for the password, without being used up.
            $steps['get authenticator with the code'] = $server->json('POST', '/api/two-factor/get-authenticator', ['otp' => $code], $auth);
            $steps['get authenticator with a wrong code'] = $server->json('POST', '/api/two-factor/get-authenticator', ['otp' => 'nope'], $auth);
            $steps['verify'] = $server->json('POST', '/api/accounts/verify-otp', ['OTP' => $code], $auth);
            $steps['verify again'] = $server->json('POST', '/api/accounts/verify-otp', ['OTP' => $code], $auth);

            return $steps;
        });
    }

    /**
     * Security keys, answered by a software authenticator for the servers'
     * default DOMAIN (http://localhost).
     */
    #[Parity('route:POST /api/two-factor/get-webauthn')]
    #[Parity('route:POST /api/two-factor/get-webauthn-challenge')]
    #[Parity('route:POST /api/two-factor/webauthn')]
    #[Parity('route:PUT /api/two-factor/webauthn')]
    #[Parity('route:DELETE /api/two-factor/webauthn')]
    #[Parity('route:DELETE /api/two-factor/webauthn/all')]
    public function test_webauthn(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, '2fa-webauthn@example.com');
            $login = LoginTest::loginFields('2fa-webauthn@example.com');
            $password = ['masterPasswordHash' => 'client-hash'];
            $first = new SoftwareAuthenticator;
            $steps = [];

            $steps['get webauthn'] = $setup = $server->json('POST', '/api/two-factor/get-webauthn', $password, $auth);
            $token = $setup->jsonString('userVerificationToken');
            $steps['challenge with a bad token'] = $server->json('POST', '/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => 'nope'], $auth);
            $steps['challenge'] = $challenge = $server->json('POST', '/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => $token], $auth);
            $activate = ['id' => 1, 'name' => 'First key', 'userVerificationToken' => $token];
            $steps['activate from another origin'] = $server->json('POST', '/api/two-factor/webauthn', [...$activate,
                'deviceResponse' => $first->register(self::options($challenge), origin: 'https://evil.example')], $auth);
            $steps['activate without challenge'] = $server->json('POST', '/api/two-factor/webauthn', [...$activate,
                'deviceResponse' => $first->register(self::options($challenge))], $auth);
            $challenge = $server->json('POST', '/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => $token], $auth);
            $steps['activate with a login response'] = $server->json('POST', '/api/two-factor/webauthn', [...$activate,
                'deviceResponse' => $first->register(self::options($challenge), type: 'webauthn.get')], $auth);
            $challenge = $server->json('POST', '/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => $token], $auth);
            $steps['activate without device response'] = $server->json('POST', '/api/two-factor/webauthn', $activate, $auth);
            $steps['activate'] = $server->json('POST', '/api/two-factor/webauthn', [...$activate, 'deviceResponse' => $first->register(self::options($challenge))], $auth);
            $steps['get webauthn again'] = $enabled = $server->json('POST', '/api/two-factor/get-webauthn', $password, $auth);
            $steps['methods'] = $server->send('GET', '/api/two-factor', $auth);

            // More keys, in the other attestation formats.
            $others = ['packed' => new SoftwareAuthenticator, 'packed-x5c' => new SoftwareAuthenticator, 'fido-u2f' => new SoftwareAuthenticator];
            $steps['challenge with the old token'] = $server->json('POST', '/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => $token], $auth);
            $id = 2;
            foreach ($others as $format => $other) {
                $token = $server->json('POST', '/api/two-factor/get-webauthn', $password, $auth)->jsonString('userVerificationToken');
                $steps["challenge for {$format}"] = $challenge = $server->json('POST', '/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => $token], $auth);
                $steps["activate {$format}"] = $server->json('PUT', '/api/two-factor/webauthn', ['id' => $id++, 'name' => $format, 'userVerificationToken' => $token,
                    'deviceResponse' => $other->register(self::options($challenge), $format)], $auth);
            }
            $steps['activate with the token of fewer keys'] = $server->json('POST', '/api/two-factor/webauthn', [...$activate, 'id' => 9,
                'userVerificationToken' => $enabled->jsonString('userVerificationToken'), 'deviceResponse' => $first->register(self::options($challenge))], $auth);

            $steps['login without code'] = $prompt = $server->form('/identity/connect/token', $login);
            $steps['login with a tampered signature'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '7',
                'two_factor_token' => $first->assert(self::request($prompt), tamper: true)]);
            $steps['login without challenge'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '7',
                'two_factor_token' => $first->assert(self::request($prompt))]);
            $server->form('/identity/connect/token', $login);
            $steps['login with garbage'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '7', 'two_factor_token' => 'nope']);
            $prompt = $server->form('/identity/connect/token', $login);
            $steps['login from another origin'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '7',
                'two_factor_token' => $first->assert(self::request($prompt), origin: 'https://evil.example')]);
            $prompt = $server->form('/identity/connect/token', $login);
            $steps['login'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '7',
                'two_factor_token' => $first->assert(self::request($prompt), counter: 7)]);
            $prompt = $server->form('/identity/connect/token', $login);
            $steps['login with the same counter'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '7',
                'two_factor_token' => $first->assert(self::request($prompt), counter: 7)]);
            $prompt = $server->form('/identity/connect/token', $login);
            $steps['login with the fido-u2f key'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '7',
                'two_factor_token' => $others['fido-u2f']->assert(self::request($prompt))]);

            $token = $server->json('POST', '/api/two-factor/get-webauthn', $password, $auth)->jsonString('userVerificationToken');
            $steps['delete an unknown key'] = $server->json('DELETE', '/api/two-factor/webauthn', ['id' => 9, 'userVerificationToken' => $token], $auth);
            $steps['delete a key'] = $server->json('DELETE', '/api/two-factor/webauthn', ['id' => 2, 'userVerificationToken' => $token], $auth);
            $steps['delete with the old token'] = $server->json('DELETE', '/api/two-factor/webauthn/all', ['userVerificationToken' => $token], $auth);
            $token = $server->json('POST', '/api/two-factor/get-webauthn', $password, $auth)->jsonString('userVerificationToken');
            $steps['delete all'] = $server->json('DELETE', '/api/two-factor/webauthn/all', ['userVerificationToken' => $token], $auth);
            $steps['delete all again'] = $server->json('DELETE', '/api/two-factor/webauthn/all', ['userVerificationToken' => $token], $auth);
            $steps['methods at last'] = $server->send('GET', '/api/two-factor', $auth);
            $steps['login at last'] = $server->form('/identity/connect/token', $login);

            return $steps;
        });
    }

    /**
     * On the features pair, whose Yubico server is a fake (.github/scripts/fake-services.php).
     */
    #[Parity('route:POST /api/two-factor/get-yubikey')]
    #[Parity('route:POST /api/two-factor/yubikey')]
    #[Parity('route:PUT /api/two-factor/yubikey')]
    #[Parity('route:DELETE /api/two-factor/yubikey')]
    #[Parity('config:_ENABLE_YUBICO')]
    #[Parity('config:YUBICO_CLIENT_ID')]
    #[Parity('config:YUBICO_SECRET_KEY')]
    #[Parity('config:YUBICO_SERVER')]
    public function test_yubikeys(): void
    {
        $this->assertSameFlowsOn((string) getenv('VW_FEATURES_REFERENCE_URL'), (string) getenv('VW_FEATURES_SUBJECT_URL'), function (Server $server): array {
            [$auth] = CipherTest::session($server, '2fa-yubi@example.com');
            $login = LoginTest::loginFields('2fa-yubi@example.com');
            $password = ['masterPasswordHash' => 'client-hash'];
            $key = 'ccccccbcgujh';
            $steps = [];

            $steps['get yubikey with a wrong password'] = $server->json('POST', '/api/two-factor/get-yubikey', ['masterPasswordHash' => 'wrong'], $auth);
            $steps['get yubikey'] = $setup = $server->json('POST', '/api/two-factor/get-yubikey', $password, $auth);
            $token = ['nfc' => true, 'userVerificationToken' => $setup->jsonString('userVerificationToken')];

            $steps['activate without keys'] = self::activateYubikey($server, $auth, $token, ['key1' => '', 'key2' => null]);
            $steps['activate without nfc'] = $server->json('POST', '/api/two-factor/yubikey', ['key1' => self::otp($key),
                'userVerificationToken' => $token['userVerificationToken']], $auth);
            $steps['activate with a bad token'] = self::activateYubikey($server, $auth, $token, ['key1' => self::otp($key), 'userVerificationToken' => 'nope']);
            $steps['activate with a short key'] = self::activateYubikey($server, $auth, $token, ['key1' => 'cccccc']);
            $steps['activate with a rejected OTP'] = self::activateYubikey($server, $auth, $token, ['key1' => self::otp($key, 'vvvv')]);
            $steps['activate with a replayed OTP'] = self::activateYubikey($server, $auth, $token, ['key1' => self::otp($key, 'rrrr')]);
            $steps['activate with another nonce'] = self::activateYubikey($server, $auth, $token, ['key1' => self::otp($key, 'nnnn')]);
            $steps['activate with a wrong signature'] = self::activateYubikey($server, $auth, $token, ['key1' => self::otp($key, 'ssss')]);
            // A key id of 12 characters is not checked.
            $steps['activate'] = self::activateYubikey($server, $auth, $token, ['key1' => self::otp($key), 'key2' => null, 'key3' => 'ccccccdddddd', 'key4' => '']);
            $steps['get yubikey again'] = $enabled = $server->json('POST', '/api/two-factor/get-yubikey', $password, $auth);
            $steps['methods'] = $server->send('GET', '/api/two-factor', $auth);

            $steps['login without code'] = $server->form('/identity/connect/token', $login);
            $steps['login with a short OTP'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '3', 'two_factor_token' => 'abc']);
            $steps['login with an unknown key'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '3', 'two_factor_token' => self::otp('cccccceeeeee')]);
            $steps['login with a rejected OTP'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '3', 'two_factor_token' => self::otp($key, 'vvvv')]);
            $steps['login with a wrong signature'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '3', 'two_factor_token' => self::otp($key, 'ssss')]);
            $steps['login'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '3', 'two_factor_token' => self::otp($key)]);
            $steps['login with the other key'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '3', 'two_factor_token' => self::otp('ccccccdddddd')]);

            $steps['activate with the old token'] = self::activateYubikey($server, $auth, $token, ['key1' => self::otp($key)]);
            $replace = ['key1' => 'ccccccffffff', 'nfc' => false, 'userVerificationToken' => $enabled->jsonString('userVerificationToken')];
            $steps['replace the keys'] = $server->json('PUT', '/api/two-factor/yubikey', $replace, $auth);
            $steps['get yubikey after replacing'] = $replaced = $server->json('POST', '/api/two-factor/get-yubikey', $password, $auth);
            $steps['login after replacing'] = $server->form('/identity/connect/token', $login);
            $steps['delete with the old token'] = $server->json('DELETE', '/api/two-factor/yubikey', ['userVerificationToken' => $enabled->jsonString('userVerificationToken')], $auth);
            $steps['delete'] = $server->json('DELETE', '/api/two-factor/yubikey', ['userVerificationToken' => $replaced->jsonString('userVerificationToken')], $auth);
            $steps['methods at last'] = $server->send('GET', '/api/two-factor', $auth);

            return $steps;
        });
    }

    /**
     * On the features pair, whose Duo is a fake (.github/scripts/fake-services.php)
     * with global keys. The test plays the client: it follows the AuthUrl,
     * which redirects back at once with a code.
     */
    #[Parity('route:POST /api/two-factor/get-duo')]
    #[Parity('route:POST /api/two-factor/duo')]
    #[Parity('route:PUT /api/two-factor/duo')]
    #[Parity('route:DELETE /api/two-factor/duo')]
    #[Parity('config:_ENABLE_DUO')]
    #[Parity('config:DUO_IKEY')]
    #[Parity('config:DUO_SKEY')]
    #[Parity('config:DUO_HOST')]
    #[Parity('config:HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS')]
    public function test_duo(): void
    {
        $this->assertSameFlowsOn((string) getenv('VW_FEATURES_REFERENCE_URL'), (string) getenv('VW_FEATURES_SUBJECT_URL'), function (Server $server): array {
            [$auth] = CipherTest::session($server, '2fa-duo@example.com');
            $login = LoginTest::loginFields('2fa-duo@example.com');
            $password = ['masterPasswordHash' => 'client-hash'];
            $default = '<To use the global Duo keys, please leave these fields untouched>';
            $userKeys = ['host' => (string) getenv('VW_SERVICES_HOST'), 'clientId' => 'DIDIFFERENTIALUSER00', 'clientSecret' => self::duoSecret('DIDIFFERENTIALUSER00')];
            $steps = [];

            $steps['get duo'] = $setup = $server->json('POST', '/api/two-factor/get-duo', $password, $auth);
            $token = ['userVerificationToken' => $setup->jsonString('userVerificationToken')];
            $steps['activate with a bad token'] = $server->json('POST', '/api/two-factor/duo', [...$userKeys, 'userVerificationToken' => 'nope'], $auth);
            $steps['activate without client id'] = $server->json('POST', '/api/two-factor/duo', ['host' => $default, 'clientSecret' => $default, ...$token], $auth);
            $steps['activate with a wrong secret'] = $server->json('POST', '/api/two-factor/duo', [...$userKeys, 'clientSecret' => 'wrong', ...$token], $auth);
            $steps['activate with the global keys'] = $server->json('POST', '/api/two-factor/duo', ['host' => $default, 'clientId' => $default, 'clientSecret' => ' ', ...$token], $auth);
            $steps['get duo with the global keys'] = $global = $server->json('POST', '/api/two-factor/get-duo', $password, $auth);
            $steps['methods'] = $server->send('GET', '/api/two-factor', $auth);

            $steps['login without code'] = $prompt = $server->form('/identity/connect/token', $login);
            [$code, $state] = self::duoCode($prompt);
            $steps['login with a bare code'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '2', 'two_factor_token' => $code]);
            $steps['login with an unknown state'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '2', 'two_factor_token' => "{$code}|nope"]);
            $steps['login'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '2', 'two_factor_token' => "{$code}|{$state}"]);
            $steps['login with the used state'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '2', 'two_factor_token' => "{$code}|{$state}"]);
            [, $state] = self::duoCode($server->form('/identity/connect/token', $login));
            $steps['login with a wrong code'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '2', 'two_factor_token' => "nope|{$state}"]);

            // The token from before the first activation still says "disabled".
            $steps['activate with user keys'] = $server->json('PUT', '/api/two-factor/duo', [...$userKeys, ...$token], $auth);
            $steps['get duo with user keys'] = $user = $server->json('POST', '/api/two-factor/get-duo', $password, $auth);
            $steps['login without code for user keys'] = $prompt = $server->form('/identity/connect/token', $login);
            [$code, $state] = self::duoCode($prompt);
            $steps['login with user keys'] = $server->form('/identity/connect/token', [...$login, 'two_factor_provider' => '2', 'two_factor_token' => "{$code}|{$state}"]);

            $steps['disable with the token of the global keys'] = $server->json('DELETE', '/api/two-factor/duo', ['userVerificationToken' => $global->jsonString('userVerificationToken')], $auth);
            $steps['disable'] = $server->json('DELETE', '/api/two-factor/duo', ['userVerificationToken' => $user->jsonString('userVerificationToken')], $auth);
            $steps['methods at last'] = $server->send('GET', '/api/two-factor', $auth);

            return $steps;
        });
    }

    /**
     * The mail pair sets up email 2FA for verified sign-ups
     * (EMAIL_2FA_ENFORCE_ON_VERIFIED_INVITE). A new user's method is stored
     * before the user, so only invited users, who exist already, get one.
     */
    #[Parity('config:EMAIL_2FA_ENFORCE_ON_VERIFIED_INVITE')]
    public function test_email_two_factor_at_sign_up(): void
    {
        $this->assertSameMailFlows(function (Server $server): array {
            [$owner] = CipherTest::session($server, 'signup-owner@example.com');
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $steps = [];

            $steps['invite'] = $server->json('POST', "/api/organizations/{$org}/users/invite", ['emails' => ['signup-invited@example.com'], 'groups' => [], 'type' => 2], $owner);
            $memberId = OrganizationTest::memberIds($server->send('GET', "/api/organizations/{$org}/users", $owner))['signup-invited@example.com'];
            $steps['register with the invitation'] = $server->json('POST', '/identity/accounts/register/finish', [...self::registration('signup-invited@example.com'),
                'orgInviteToken' => $server->mailedToken('signup-invited@example.com'), 'organizationUserId' => $memberId]);
            $steps['login of the invited'] = $server->form('/identity/connect/token', LoginTest::loginFields('signup-invited@example.com'));
            $steps['send login code'] = $server->json('POST', '/api/two-factor/send-email-login', ['email' => 'signup-invited@example.com', 'masterPasswordHash' => 'client-hash']);
            [$steps['login code mail'], $code] = self::codeMail($server, 'signup-invited@example.com');
            $steps['login with the code'] = $login = $server->form('/identity/connect/token', [...LoginTest::loginFields('signup-invited@example.com'),
                'two_factor_provider' => '1', 'two_factor_token' => $code]);
            $steps['methods of the invited'] = $server->send('GET', '/api/two-factor', ['Authorization' => 'Bearer '.$login->jsonString('access_token')]);

            $steps['register verified'] = $server->json('POST', '/identity/accounts/register/finish', [...self::registration('signup-new@example.com'),
                'emailVerificationToken' => $this->registerToken('signup-new@example.com')]);
            $steps['login of the new user'] = $server->form('/identity/connect/token', LoginTest::loginFields('signup-new@example.com'));

            return $steps;
        });
    }

    /**
     * The mail pair sets up email 2FA where verified members would lose
     * their second factor (EMAIL_2FA_AUTO_FALLBACK).
     */
    #[Parity('config:EMAIL_2FA_AUTO_FALLBACK')]
    #[Parity('route:PUT /api/organizations/{org_id}/users/{member_id}/recover-account')]
    public function test_email_two_factor_as_fallback(): void
    {
        $this->assertSameMailFlows(function (Server $server): array {
            [$owner] = CipherTest::session($server, 'fallback-owner@example.com');
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $users = "/api/organizations/{$org}/users";
            [$member, $memberUserId] = $this->verifiedSession($server, 'fallback-member@example.com');
            $memberId = self::join($server, $owner, $member, $org, 'fallback-member@example.com');
            $steps = [];

            $server->json('POST', "{$users}/{$memberId}/confirm", ['key' => '4.member-key'], $owner);
            $server->json('PUT', "/api/organizations/{$org}/policies/8", ['policy' => ['enabled' => true, 'data' => ['autoEnrollEnabled' => false]]], $owner);
            $steps['enroll'] = $server->json('PUT', "{$users}/{$memberUserId}/reset-password-enrollment", ['resetPasswordKey' => '4.reset', 'masterPasswordHash' => 'client-hash'], $member);
            $setup = $server->json('POST', '/api/two-factor/get-authenticator', ['masterPasswordHash' => 'client-hash'], $member);
            $steps['authenticator'] = $server->json('POST', '/api/two-factor/authenticator', ['key' => $setup->jsonString('authenticator.key'),
                'userVerificationToken' => $setup->jsonString('userVerificationToken'),
                'token' => AuthenticatorController::totp(Base32::decode($setup->jsonString('authenticator.key')) ?? '', time())], $member);
            $steps['reset two-factor login'] = $server->json('PUT', "{$users}/{$memberId}/recover-account", ['resetTwoFactor' => true], $owner);
            $steps['recovery mail'] = $server->mail('fallback-member@example.com')->exchange();
            $steps['methods after the reset'] = $server->send('GET', '/api/two-factor', $member);
            $steps['login after the reset'] = $server->form('/identity/connect/token', LoginTest::loginFields('fallback-member@example.com'));

            $steps['two-factor policy'] = $server->json('PUT', "/api/organizations/{$org}/policies/0", ['policy' => ['enabled' => true, 'data' => null]], $owner);
            [$late] = $this->verifiedSession($server, 'fallback-late@example.com');
            $lateId = self::join($server, $owner, $late, $org, 'fallback-late@example.com');
            $steps['confirm a verified member without 2FA'] = $server->json('POST', "{$users}/{$lateId}/confirm", ['key' => '4.member-key'], $owner);
            $steps['methods of the confirmed'] = $server->send('GET', '/api/two-factor', $late);
            [$plain] = CipherTest::session($server, 'fallback-plain@example.com');
            $server->json('POST', "{$users}/invite", ['emails' => ['fallback-plain@example.com'], 'groups' => [], 'type' => 2], $owner);
            $plainId = OrganizationTest::memberIds($server->send('GET', $users, $owner))['fallback-plain@example.com'];
            $steps['accept of an unverified member'] = $server->json('POST', "{$users}/{$plainId}/accept", ['token' => $server->mailedToken('fallback-plain@example.com')], $plain);
            $steps['confirm an unverified member'] = $server->json('POST', "{$users}/{$plainId}/confirm", ['key' => '4.member-key'], $owner);
            $steps['members'] = $server->send('GET', $users, $owner);

            return $steps;
        });
    }

    /**
     * The last mail to the address with its code, which is replaced by a placeholder.
     *
     * @return array{Exchange, string}
     */
    private static function codeMail(Server $server, string $to): array
    {
        $mail = $server->mail($to);
        if (preg_match('/\b(\d{6})\b/', $mail->text, $match) !== 1) {
            throw new \RuntimeException("No code in the mail to {$to}.");
        }
        $exchange = $mail->exchange();

        return [$exchange->withBody(str_replace($match[1], '<code>', $exchange->body)), $match[1]];
    }

    /**
     * A code that belongs to no step near now.
     */
    private static function otherCode(string $secret): string
    {
        $near = array_map(static fn (int $step): string => AuthenticatorController::totp($secret, time() + $step * 30), [-2, -1, 0, 1, 2]);
        for ($code = 0; in_array(sprintf('%06d', $code), $near, true); $code++);

        return sprintf('%06d', $code);
    }

    /**
     * POST /api/two-factor/yubikey with the keys, nfc and the token.
     *
     * @param  array<string, string>  $auth
     * @param  array{nfc: bool, userVerificationToken: string}  $token
     * @param  array<string, ?string>  $keys
     */
    private static function activateYubikey(Server $server, array $auth, array $token, array $keys): Exchange
    {
        return $server->json('POST', '/api/two-factor/yubikey', [...$token, ...$keys], $auth);
    }

    /**
     * The publicKey options of a registration challenge.
     *
     * @return array<mixed>
     */
    public static function options(Exchange $challenge): array
    {
        $options = $challenge->json('options');

        return is_array($options) ? $options : throw new \RuntimeException("No options in a {$challenge->status} response: {$challenge->body}");
    }

    /**
     * The WebAuthn options of a login prompt.
     *
     * @return array<mixed>
     */
    public static function request(Exchange $prompt): array
    {
        $request = $prompt->json('TwoFactorProviders2.7');

        return is_array($request) ? $request : throw new \RuntimeException("No WebAuthn request in a {$prompt->status} response: {$prompt->body}");
    }

    /**
     * Follows the AuthUrl of a login prompt to the fake Duo, which sends the
     * client back with a code and the state.
     *
     * @return array{string, string}
     */
    private static function duoCode(Exchange $prompt): array
    {
        $client = new Client(['verify' => (string) getenv('VW_SERVICES_CA'), 'allow_redirects' => false, 'http_errors' => false, 'timeout' => 10]);
        $location = $client->get($prompt->jsonString('TwoFactorProviders2.2.AuthUrl'))->getHeaderLine('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $code = $query['duo_code'] ?? null;
        $state = $query['state'] ?? null;

        return is_string($code) && is_string($state) ? [$code, $state] : throw new \RuntimeException("No code in the redirect to {$location}.");
    }

    /**
     * The secret the fake Duo issued with a client id.
     */
    private static function duoSecret(string $clientId): string
    {
        return substr(hash('sha256', "duo:{$clientId}"), 0, 40);
    }

    /**
     * A YubiKey OTP of the key: its id and 32 characters, which the fake
     * Yubico server judges by their end.
     */
    private static function otp(string $id, string $ending = 'dddd'): string
    {
        return $id.str_repeat('t', 28).$ending;
    }

    /**
     * Invites by mail and accepts with the mailed token; returns the membership id.
     *
     * @param  array<string, string>  $owner
     * @param  array<string, string>  $member
     */
    private static function join(Server $server, array $owner, array $member, string $org, string $email): string
    {
        $server->json('POST', "/api/organizations/{$org}/users/invite", ['emails' => [$email], 'groups' => [], 'type' => 2], $owner);
        $memberId = OrganizationTest::memberIds($server->send('GET', "/api/organizations/{$org}/users", $owner))[$email];
        $server->json('POST', "/api/organizations/{$org}/users/{$memberId}/accept", ['token' => $server->mailedToken($email)], $member);

        return $memberId;
    }

    /**
     * @return array<string, mixed>
     */
    private static function registration(string $email): array
    {
        return ['email' => $email, 'kdf' => 0, 'kdfIterations' => 600000, 'masterPasswordHash' => 'client-hash', 'key' => 'user-key',
            'keys' => ['encryptedPrivateKey' => 'private-key', 'publicKey' => 'public-key']];
    }

    /**
     * A sign-up whose address counts as verified, as when the server mailed the link.
     */
    private function registerToken(string $email): string
    {
        return $this->signedToken('register_verify', ['nbf' => time(), 'exp' => time() + 1800, 'iss' => '', 'sub' => $email, 'name' => null, 'verified' => true]);
    }

    /**
     * A user with a verified address, logged in; with the user id.
     *
     * @return array{array<string, string>, string}
     */
    private function verifiedSession(Server $server, string $email): array
    {
        $server->json('POST', '/identity/accounts/register/finish', [...self::registration($email), 'emailVerificationToken' => $this->registerToken($email)]);
        $auth = ['Authorization' => 'Bearer '.$server->form('/identity/connect/token', LoginTest::loginFields($email))->jsonString('access_token'), 'Accept' => 'application/json'];

        return [$auth, $server->send('GET', '/api/accounts/profile', $auth)->jsonString('id')];
    }

    /**
     * A user verification token for the claims of one method, which the
     * servers only issue for the keys they made.
     *
     * @param  array<string, mixed>  $claims
     */
    private function verificationToken(string $userId, array $claims): string
    {
        return $this->signedToken('api.2fa', ['nbf' => time(), 'exp' => time() + 300, 'iss' => '', 'sub' => $userId, 'enabled' => false, 'claims' => $claims]);
    }
}
