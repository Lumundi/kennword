<?php

namespace Tests\Feature\Api;

use App\Http\Data\Body;
use App\Mail\Transport;
use App\Models\Invitation;
use App\Models\User;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\Fakes\MailTransportFake;
use Tests\TestCase;

/**
 * Prelogin and registration (src/api/identity.rs, src/api/core/accounts.rs).
 */
class RegistrationTest extends TestCase
{
    use UsesVaultwardenDatabase;

    protected function vaultwardenEnvironment(): array
    {
        return ['PASSWORD_ITERATIONS' => '100000'];
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->useDatabase('sqlite');
    }

    #[Parity('route:POST /identity/accounts/prelogin')]
    #[Parity('route:POST /identity/accounts/prelogin/password')]
    public function test_prelogin_of_an_unknown_email_is_stable(): void
    {
        $first = $this->postJson('/identity/accounts/prelogin', ['email' => ' Nobody@Example.com '])->assertStatus(200);
        $second = $this->postJson('/identity/accounts/prelogin/password', ['email' => 'nobody@example.com'])->assertStatus(200);

        $this->assertSame($first->getContent(), $second->getContent());
        $this->assertSame(['kdf', 'kdfIterations', 'kdfMemory', 'kdfParallelism', 'kdfSettings', 'salt'], array_keys((array) $first->json()));
        $this->assertNull($first->json('salt'));
        $this->assertSame($first->json('kdf'), $first->json('kdfSettings.kdfType'));
    }

    #[Parity('route:POST /identity/accounts/register/send-verification-email')]
    #[Parity('route:POST /identity/accounts/register/finish')]
    public function test_json_bodies_are_limited_like_vaultwardens(): void
    {
        $prelogin = fn (string $body, array $server = []) => $this->call('POST', '/identity/accounts/prelogin',
            server: ['CONTENT_TYPE' => 'application/json', ...$server], content: $body);
        $json = '{"email":"a@example.com"}';

        $prelogin(str_pad($json, Body::JSON_LIMIT))->assertStatus(200);
        $prelogin(str_pad($json, Body::JSON_LIMIT + 1))->assertStatus(413)->assertSee('Payload Too Large');
        $prelogin($json, ['CONTENT_LENGTH' => (string) (Body::JSON_LIMIT + 1)])->assertStatus(413);
    }

    #[Parity('route:POST /identity/accounts/register/verification-email-clicked')]
    public function test_the_link_of_the_verification_mail(): void
    {
        $clicked = fn (string $email, mixed $token) => $this->postJson('/identity/accounts/register/verification-email-clicked',
            ['email' => $email, 'emailVerificationToken' => $token]);
        $expired = 'Expired link. Please restart registration or try logging in. You may already have an account';

        // Without mail, the token is not verified.
        $token = $this->postJson('/identity/accounts/register/send-verification-email', ['email' => 'grace@example.com'])->json();
        $clicked('grace@example.com', $token)->assertStatus(400)->assertJsonPath('message', $expired);

        $mails = new MailTransportFake;
        $this->app->instance(Transport::class, $mails);
        $this->changeVaultwardenEnvironment(['SMTP_HOST' => 'localhost', 'SMTP_FROM' => 'vault@example.com', 'SIGNUPS_VERIFY' => 'true']);
        $this->postJson('/identity/accounts/register/send-verification-email', ['email' => 'grace@example.com'])->assertStatus(204);
        // Vaultwarden 42660af7: the link says it comes from the mail.
        if (preg_match('~/#/finish-signup/\?email=grace%40example\.com&token=([^&"\s]+)&fromEmail=true~', $mails->last('grace@example.com')['text'], $link) !== 1) {
            $this->fail('No link in the mail.');
        }
        $token = $link[1];

        $clicked('GRACE@example.com', $token)->assertStatus(200)->assertContent('');
        $clicked('other@example.com', $token)->assertStatus(400)->assertJsonPath('message', $expired);
        $clicked('grace@example.com', 'nope')->assertStatus(400)->assertJsonPath('message', $expired);
        $this->postJson('/identity/accounts/register/verification-email-clicked', ['email' => 'grace@example.com'])->assertStatus(422);

        // Once the account exists, the link is used up.
        $this->postJson('/identity/accounts/register/finish', ['email' => 'grace@example.com', 'emailVerificationToken' => $token, 'kdf' => 0, 'kdfIterations' => 600000,
            'masterPasswordHash' => 'client-hash', 'key' => 'user-key', 'keys' => ['encryptedPrivateKey' => 'private', 'publicKey' => 'public']])->assertStatus(200);
        $clicked('grace@example.com', $token)->assertStatus(400)->assertJsonPath('message', $expired);
    }

    public function test_registration_with_the_old_format(): void
    {
        $token = $this->postJson('/identity/accounts/register/send-verification-email', ['email' => 'frank@example.com', 'name' => 'Frank'])
            ->assertStatus(200)->assertHeader('Content-Type', 'application/json')->json();
        $this->assertIsString($token);

        $this->postJson('/identity/accounts/register/finish', [
            'email' => 'frank@example.com',
            'emailVerificationToken' => $token,
            'kdf' => 0,
            'kdfIterations' => 600000,
            'masterPasswordHash' => 'client-hash',
            'key' => 'user-key',
            'keys' => ['encryptedPrivateKey' => 'private', 'publicKey' => 'public'],
            'masterPasswordHint' => '  hint ',
        ])->assertStatus(200)->assertContent('{"object":"registerFinish"}');

        $user = User::findByMail('frank@example.com');
        $this->assertNotNull($user);
        $this->assertSame('Frank', $user->name);
        $this->assertTrue($user->checkValidPassword('client-hash'));
        $this->assertSame('user-key', $user->akey);
        $this->assertSame('public', $user->public_key);
        $this->assertSame('hint', $user->password_hint);
        $this->assertNull($user->verified_at);

        $this->postJson('/identity/accounts/prelogin', ['email' => 'frank@example.com'])
            ->assertJsonPath('kdf', 0)->assertJsonPath('kdfIterations', 600000);
    }

    public function test_registration_with_the_current_format(): void
    {
        $token = $this->tokenFor('grace@example.com');
        $kdf = ['kdfType' => 1, 'iterations' => 3, 'memory' => 64, 'parallelism' => 4];

        $this->postJson('/identity/accounts/register/finish', [
            'email' => 'Grace@Example.com',
            'emailVerificationToken' => $token,
            'masterPasswordAuthentication' => ['kdf' => $kdf, 'salt' => 'grace@example.com', 'masterPasswordAuthenticationHash' => 'hash'],
            'masterPasswordUnlock' => ['kdf' => $kdf, 'salt' => 'grace@example.com', 'masterKeyWrappedUserKey' => 'wrapped'],
        ], ['Accept' => 'application/json'])->assertStatus(400)->assertJsonPath('message', 'Email verification token does not match email');

        $this->postJson('/identity/accounts/register/finish', [
            'email' => 'grace@example.com',
            'emailVerificationToken' => $token,
            'masterPasswordAuthentication' => ['kdf' => $kdf, 'salt' => 'grace@example.com', 'masterPasswordAuthenticationHash' => 'hash'],
            'masterPasswordUnlock' => ['kdf' => $kdf, 'salt' => 'grace@example.com', 'masterKeyWrappedUserKey' => 'wrapped'],
        ])->assertStatus(200);

        $user = User::findByMail('grace@example.com');
        $this->assertNotNull($user);
        $this->assertSame([1, 3, 64, 4], [$user->client_kdf_type, $user->client_kdf_iter, $user->client_kdf_memory, $user->client_kdf_parallelism]);
        $this->assertSame('wrapped', $user->akey);
        $this->assertTrue($user->checkValidPassword('hash'));
    }

    public function test_the_verification_token_is_plain_text_unless_json_is_asked_for(): void
    {
        $response = $this->call('POST', '/identity/accounts/register/send-verification-email', content: '{"email":"x@example.com"}');

        $response->assertStatus(200)->assertHeader('Content-Type', 'text/plain; charset=utf-8');
        $this->assertStringStartsWith('eyJ', (string) $response->getContent());
    }

    public function test_registration_errors(): void
    {
        $token = $this->tokenFor('henry@example.com');
        $base = ['email' => 'henry@example.com', 'emailVerificationToken' => $token, 'kdf' => 0, 'kdfIterations' => 600000,
            'masterPasswordHash' => 'h', 'key' => 'k'];

        $this->postJson('/identity/accounts/register/finish', [...$base, 'kdfIterations' => 5000])
            ->assertStatus(400)->assertJsonPath('message', 'PBKDF2 KDF iterations must be at least 100000.');
        $this->postJson('/identity/accounts/register/finish', ['email' => 'henry@example.com', 'kdf' => 0, 'kdfIterations' => 600000, 'masterPasswordHash' => 'h', 'key' => 'k'])
            ->assertStatus(400)->assertJsonPath('message', 'Registration is missing required parameters');
        $this->postJson('/identity/accounts/register/finish', ['email' => 'henry@example.com'])->assertStatus(422);
        $this->postJson('/identity/accounts/register/finish', [...$base, 'kdf' => '0'])->assertStatus(422);
        $this->call('POST', '/identity/accounts/register/finish', content: '{not json')->assertStatus(400);

        $this->postJson('/identity/accounts/register/finish', $base)->assertStatus(200);
        $this->postJson('/identity/accounts/register/finish', $base)
            ->assertStatus(400)->assertJsonPath('message', 'Registration not allowed or user already exists');
    }

    #[Parity('config:SIGNUPS_ALLOWED')]
    public function test_closed_signups_still_allow_invited_users(): void
    {
        $this->changeVaultwardenEnvironment(['SIGNUPS_ALLOWED' => 'false']);

        $this->postJson('/identity/accounts/register/send-verification-email', ['email' => 'ida@example.com'])
            ->assertStatus(400)->assertJsonPath('message', 'Registration not allowed or user already exists');

        Invitation::new('ida@example.com')->save();
        $token = $this->postJson('/identity/accounts/register/send-verification-email', ['email' => 'ida@example.com'])->assertStatus(200)->json();
        $this->assertIsString($token);
        $this->postJson('/identity/accounts/register/finish', ['email' => 'ida@example.com', 'emailVerificationToken' => $token,
            'kdf' => 0, 'kdfIterations' => 600000, 'masterPasswordHash' => 'h', 'key' => 'k'])->assertStatus(200);
        $this->assertNull(Invitation::findByMail('ida@example.com'));
    }

    #[Parity('config:UNAUTHENTICATED_RATELIMIT_SECONDS')]
    #[Parity('config:UNAUTHENTICATED_RATELIMIT_MAX_BURST')]
    public function test_unauthenticated_requests_are_rate_limited(): void
    {
        for ($i = 0; $i < 50; $i++) {
            $this->postJson('/identity/accounts/prelogin', ['email' => 'a@example.com'])->assertStatus(200);
        }

        $this->postJson('/identity/accounts/prelogin', ['email' => 'a@example.com'])
            ->assertStatus(429)->assertJsonPath('message', 'Too many requests');
    }

    private function tokenFor(string $email): string
    {
        $token = $this->postJson('/identity/accounts/register/send-verification-email', ['email' => $email])->json();
        $this->assertIsString($token);

        return $token;
    }
}
