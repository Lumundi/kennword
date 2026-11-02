<?php

namespace Tests\Differential;

use Tests\Attributes\Parity;

/**
 * Prelogin and registration on both servers. They share the RSA key (see
 * differential.sh), so unknown emails get the same KDF settings.
 */
class RegistrationTest extends DifferentialTestCase
{
    #[Parity('route:POST /identity/accounts/prelogin')]
    #[Parity('route:POST /identity/accounts/prelogin/password')]
    public function test_prelogin(): void
    {
        foreach (['unknown@example.com', ' Mixed.Case@Example.COM ', 'another.unknown@example.org'] as $email) {
            $this->assertSameResponses('POST', '/identity/accounts/prelogin', ['Content-Type' => 'application/json'], (string) json_encode(['email' => $email]));
            $this->assertSameResponses('POST', '/identity/accounts/prelogin/password', ['Content-Type' => 'application/json'], (string) json_encode(['email' => $email]));
        }
    }

    public function test_malformed_bodies(): void
    {
        $this->assertSameResponses('POST', '/identity/accounts/prelogin', ['Accept' => 'application/json'], '{"email": ');
        $this->assertSameResponses('POST', '/identity/accounts/prelogin', ['Accept' => 'application/json'], '{"mail": "a@example.com"}');
        $this->assertSameResponses('POST', '/identity/accounts/prelogin', ['Accept' => 'application/json'], '{"email": 5}');
        $this->assertSameResponses('POST', '/identity/accounts/prelogin', ['Accept' => 'application/json'], '');
        $this->assertSameResponses('POST', '/identity/accounts/register/finish', ['Accept' => 'application/json'], '{"email": "a@example.com"}');
    }

    #[Parity('route:POST /identity/accounts/register/send-verification-email')]
    public function test_verification_token(): void
    {
        $body = (string) json_encode(['email' => 'token@example.com', 'name' => 'Token']);
        $this->assertSameResponses('POST', '/identity/accounts/register/send-verification-email', ['Accept' => 'application/json'], $body);
        $this->assertSameResponses('POST', '/identity/accounts/register/send-verification-email', [], $body);
        $this->assertSameResponses('POST', '/identity/accounts/register/send-verification-email', ['Accept' => 'text/plain, application/json'], $body);
    }

    /**
     * Vaultwarden 42660af7: the link of the verification mail asks whether it still leads to a registration.
     */
    #[Parity('route:POST /identity/accounts/register/verification-email-clicked')]
    public function test_verification_email_clicked(): void
    {
        $token = fn (string $email, bool $verified, int $exp = 1800): string => $this->signedToken('register_verify',
            ['nbf' => time() - 60, 'exp' => time() + $exp, 'iss' => '', 'sub' => $email, 'name' => null, 'verified' => $verified]);
        $verified = $token('Clicked@Example.com', true);
        $unverified = $token('clicked@example.com', false);
        $expired = $token('clicked@example.com', true, -3600);
        $registered = $token('clicked-registered@example.com', true);

        $this->assertSameFlows(function (Server $server) use ($verified, $unverified, $expired, $registered): array {
            LoginTest::register($server, 'clicked-registered@example.com');
            $clicked = '/identity/accounts/register/verification-email-clicked';
            $steps = [];

            $steps['verified'] = $server->json('POST', $clicked, ['email' => 'clicked@example.com', 'emailVerificationToken' => $verified]);
            $steps['unverified'] = $server->json('POST', $clicked, ['email' => 'clicked@example.com', 'emailVerificationToken' => $unverified]);
            $steps['expired'] = $server->json('POST', $clicked, ['email' => 'clicked@example.com', 'emailVerificationToken' => $expired]);
            $steps['other email'] = $server->json('POST', $clicked, ['email' => 'other@example.com', 'emailVerificationToken' => $verified]);
            $steps['not a token'] = $server->json('POST', $clicked, ['email' => 'clicked@example.com', 'emailVerificationToken' => 'nope']);
            $steps['registered'] = $server->json('POST', $clicked, ['email' => 'clicked-registered@example.com', 'emailVerificationToken' => $registered]);
            $steps['without token'] = $server->json('POST', $clicked, ['email' => 'clicked@example.com']);
            $token = $server->json('POST', '/identity/accounts/register/send-verification-email', ['email' => 'clicked-new@example.com'], ['Accept' => 'application/json'])->json();
            $steps['token of the server'] = $server->json('POST', $clicked, ['email' => 'clicked-new@example.com', 'emailVerificationToken' => $token]);

            return $steps;
        });
    }

    #[Parity('route:POST /identity/accounts/register/finish')]
    public function test_registration_with_the_old_format(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            $steps = [];
            $steps['token'] = $server->json('POST', '/identity/accounts/register/send-verification-email', ['email' => 'old@example.com', 'name' => 'Old Format'], ['Accept' => 'application/json']);
            $token = json_decode($steps['token']->body);

            $register = [
                'email' => 'old@example.com',
                'emailVerificationToken' => $token,
                'kdf' => 0,
                'kdfIterations' => 600000,
                'masterPasswordHash' => 'old-client-hash',
                'masterPasswordHint' => ' a hint ',
                'key' => 'user-key',
                'keys' => ['encryptedPrivateKey' => 'private-key', 'publicKey' => 'public-key'],
            ];
            $steps['too few iterations'] = $server->json('POST', '/identity/accounts/register/finish', [...$register, 'kdfIterations' => 5000]);
            $steps['register'] = $server->json('POST', '/identity/accounts/register/finish', $register);
            $steps['again'] = $server->json('POST', '/identity/accounts/register/finish', $register);
            $steps['prelogin'] = $server->json('POST', '/identity/accounts/prelogin', ['email' => 'OLD@example.com']);

            return $steps;
        });
    }

    public function test_registration_with_the_current_format(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            $steps = [];
            $steps['token'] = $server->json('POST', '/identity/accounts/register/send-verification-email', ['email' => 'current@example.com'], ['Accept' => 'application/json']);
            $token = json_decode($steps['token']->body);

            $kdf = ['kdfType' => 1, 'iterations' => 3, 'memory' => 64, 'parallelism' => 4];
            $register = [
                'email' => 'current@example.com',
                'emailVerificationToken' => $token,
                'masterPasswordAuthentication' => ['kdf' => $kdf, 'salt' => 'current@example.com', 'masterPasswordAuthenticationHash' => 'hash'],
                'masterPasswordUnlock' => ['kdf' => $kdf, 'salt' => 'current@example.com', 'masterKeyWrappedUserKey' => 'wrapped'],
            ];
            $steps['salt mismatch'] = $server->json('POST', '/identity/accounts/register/finish', [...$register,
                'masterPasswordUnlock' => ['kdf' => $kdf, 'salt' => 'other@example.com', 'masterKeyWrappedUserKey' => 'wrapped']]);
            $steps['missing parameters'] = $server->json('POST', '/identity/accounts/register/finish', [...$register, 'emailVerificationToken' => null]);
            $steps['register'] = $server->json('POST', '/identity/accounts/register/finish', $register);
            $steps['prelogin'] = $server->json('POST', '/identity/accounts/prelogin', ['email' => 'current@example.com']);

            return $steps;
        });
    }
}
