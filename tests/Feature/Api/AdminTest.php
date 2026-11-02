<?php

namespace Tests\Feature\Api;

use App\Auth\AdminToken;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Http\Controllers\AdminController;
use App\Mail\Transport;
use App\Models\Event;
use App\Models\Invitation;
use App\Models\Membership;
use App\Models\Organization;
use App\Models\User;
use App\Support\Release;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Tests\Attributes\Parity;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\Fakes\MailTransportFake;
use Tests\TestCase;

/**
 * The admin panel (src/api/admin.rs) with ADMIN_TOKEN, without it and with
 * DISABLE_ADMIN_TOKEN. tests/Differential/AdminTest compares it with Vaultwarden.
 */
class AdminTest extends TestCase
{
    use UsesVaultwardenDatabase;

    private const string TOKEN = 'admin-token';

    protected function vaultwardenEnvironment(): array
    {
        return match ($this->name()) {
            'test_without_a_token_the_panel_is_disabled' => [],
            'test_disable_admin_token_needs_no_session' => ['DISABLE_ADMIN_TOKEN' => 'true'],
            default => ['ADMIN_TOKEN' => self::TOKEN, 'PASSWORD_ITERATIONS' => '100000'],
        };
    }

    #[Parity('route:GET /admin')]
    public function test_without_a_token_the_panel_is_disabled(): void
    {
        $this->get('/admin')->assertStatus(200)->assertHeader('Content-Type', 'text/plain; charset=utf-8')
            ->assertContent("The admin panel is disabled, please configure the 'ADMIN_TOKEN' variable to enable it");
        $this->form('/admin', ['token' => self::TOKEN])->assertStatus(404);
        $this->get('/admin/users', ['Accept' => 'application/json'])->assertStatus(404);
    }

    #[Parity('config:DISABLE_ADMIN_TOKEN')]
    public function test_disable_admin_token_needs_no_session(): void
    {
        $this->useDatabase('sqlite');

        $this->get('/admin')->assertStatus(200)->assertSee('id="config-form"', false);
        $this->get('/admin/users')->assertStatus(200)->assertExactJson([]);
        $this->form('/admin', ['token' => ''])->assertStatus(401);
    }

    #[Parity('route:GET /admin#admin_page_login')]
    #[Parity('route:POST /admin')]
    #[Parity('route:GET /admin/logout')]
    #[Parity('config:ADMIN_TOKEN')]
    #[Parity('config:ADMIN_SESSION_LIFETIME')]
    public function test_login_sets_a_session_cookie(): void
    {
        $this->useDatabase('sqlite');

        $this->get('/admin')->assertStatus(200)->assertSee('Authentication key needed to continue')->assertDontSee('name="redirect"', false);
        $this->form('/admin', ['token' => 'wrong', 'redirect' => '/users'])->assertStatus(401)
            ->assertSee('Error: Invalid admin token, please try again.')->assertSee('value="//users"', false);
        $this->form('/admin', ['redirect' => '/users'])->assertStatus(422);
        $this->postJson('/admin', ['token' => self::TOKEN])->assertStatus(404);

        $login = $this->form('/admin', ['token' => ' '.self::TOKEN."\n"])->assertStatus(200)->assertSee('id="config-form"', false);
        $cookie = $this->sessionCookie($login);
        $this->assertSame('/admin', $cookie->getPath());
        $this->assertSame(1200, $cookie->getMaxAge());
        $this->assertTrue($cookie->isHttpOnly());
        $this->assertFalse($cookie->isSecure());
        $this->assertSame(Cookie::SAMESITE_STRICT, $cookie->getSameSite());
        $this->assertSame("VW_ADMIN={$cookie->getValue()}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=1200", (string) $cookie);
        $claims = $this->app->make(Jwt::class)->decode((string) $cookie->getValue(), JwtIssuer::Admin, fields: AdminToken::CLAIMS);
        $this->assertSame(['nbf', 'exp', 'iss', 'sub'], array_keys($claims));
        $this->assertSame('admin_panel', $claims['sub']);

        // Behind a proxy that terminates TLS the cookie is only sent over HTTPS; the lifetime is a setting.
        $this->changeVaultwardenEnvironment(['ADMIN_SESSION_LIFETIME' => '5']);
        $secure = $this->form('/admin', ['token' => self::TOKEN, 'redirect' => '/users/overview'], ['X-Forwarded-Proto' => 'https'])
            ->assertStatus(303)->assertHeader('Location', '/admin/users/overview')->assertHeaderMissing('Content-Type');
        $this->assertSame("VW_ADMIN={$this->sessionCookie($secure)->getValue()}; HttpOnly; SameSite=Strict; Secure; Path=/admin; Max-Age=300",
            (string) $this->sessionCookie($secure));

        $logout = $this->withUnencryptedCookie(AdminToken::COOKIE_NAME, (string) $cookie->getValue())->get('/admin/logout')
            ->assertStatus(303)->assertHeader('Location', '/admin');
        $this->assertMatchesRegularExpression('/^VW_ADMIN=; SameSite=Lax; Path=\/admin; Max-Age=0; Expires=\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/',
            (string) $this->sessionCookie($logout));
        $this->unencryptedCookies = [];
        $this->assertSame([], $this->get('/admin/logout')->assertStatus(303)->headers->getCookies());
    }

    #[Parity('config:ADMIN_TOKEN')]
    #[Parity('config:ADMIN_RATELIMIT_*')]
    public function test_argon2_tokens_and_the_rate_limit(): void
    {
        $this->useDatabase('sqlite');
        $this->changeVaultwardenEnvironment([
            'ADMIN_TOKEN' => password_hash('secret', PASSWORD_ARGON2ID, ['memory_cost' => 8192, 'time_cost' => 1, 'threads' => 1]),
            'ADMIN_RATELIMIT_MAX_BURST' => '2',
        ]);

        $this->form('/admin', ['token' => 'wrong'])->assertStatus(401);
        $this->sessionCookie($this->form('/admin', ['token' => 'secret'])->assertStatus(200));
        $this->form('/admin', ['token' => 'secret', 'redirect' => '/diagnostics'])->assertStatus(429)
            ->assertSee('Error: Too many requests, try again later.')->assertSee('value="//diagnostics"', false);
    }

    /**
     * The admin_login catcher answers failed sessions below /admin.
     */
    #[Parity('route:GET /admin#admin_page')]
    public function test_pages_need_a_session(): void
    {
        $this->useDatabase('sqlite');

        $this->get('/admin/users/overview')->assertStatus(401)->assertSee('value="/users/overview"', false);
        $this->get('/admin/users', ['Accept' => 'application/json'])->assertStatus(401)->assertJsonPath('message', 'Authorization failed.');
        $this->postJson('/admin/users/update_revision')->assertStatus(401)->assertJsonPath('message', 'Authorization failed.');
        $this->post('/admin/users/update_revision')->assertStatus(404);
        $this->get('/admin/diagnostics/config', ['Accept' => 'text/html'])->assertStatus(404);

        $expired = $this->app->make(Jwt::class)->encode(['nbf' => time() - 7200, 'exp' => time() - 3600,
            'iss' => 'http://localhost|admin', 'sub' => 'admin_panel']);
        $response = $this->withUnencryptedCookie(AdminToken::COOKIE_NAME, $expired)->get('/admin')->assertStatus(401)->assertSee('Authentication key needed');
        // Rocket drops the removal of the cookie when the catcher answers.
        $this->assertSame([], $response->headers->getCookies());
    }

    #[Parity('route:POST /admin/config')]
    #[Parity('route:POST /admin/config/delete')]
    public function test_settings_are_saved_to_config_json(): void
    {
        $this->useDatabase('sqlite');
        $this->login();
        $file = "{$this->dataFolder}/config.json";

        $this->postJson('/admin/config', ['invitation_org_name' => 'Example', 'admin_token' => self::TOKEN, 'data_folder' => '/elsewhere',
            'sends_allowed' => null, 'icon_cache_ttl' => 5, 'unknown' => true])->assertStatus(200);
        // Only what may be edited, in the order of the settings, as serde_json writes it.
        $this->assertSame("{\n  \"admin_token\": \"admin-token\",\n  \"invitation_org_name\": \"Example\",\n  \"icon_cache_ttl\": 5\n}",
            file_get_contents($file));

        // Each request reads config.json again; the test application has to be told.
        $this->changeVaultwardenEnvironment([]);
        $page = $this->get('/admin')->assertStatus(200);
        $page->assertSee('<div class="row my-2 align-items-center is-overridden-true alert-row" title="[admin_token]', false);
        $page->assertSee('value="Example"  placeholder="Default: Vaultwarden"', false);
        $page->assertSee('<button id="b_settings" type="button" class="card-header text-start btn btn-link text-decoration-none" aria-expanded="false" aria-controls="g_settings" data-bs-toggle="collapse" data-bs-target="#g_settings"> General settings</button>', false);

        $this->postJson('/admin/config', ['password_iterations' => 1000])->assertStatus(400)
            ->assertJsonPath('message', 'Unable to save config: PASSWORD_ITERATIONS should be at least 100000 or higher. The default is 600000!');
        $this->postJson('/admin/config', ['icon_cache_ttl' => '5'])->assertStatus(422);
        $this->postJson('/admin/config', ['email_token_size' => 256])->assertStatus(422);
        $this->assertStringContainsString('"Example"', (string) file_get_contents($file));

        $this->postJson('/admin/config/delete')->assertStatus(200);
        $this->assertFileDoesNotExist($file);
        $this->postJson('/admin/config/delete')->assertStatus(200);
    }

    public function test_config_json_is_replaced_at_once_and_keeps_its_mode(): void
    {
        $this->useDatabase('sqlite');
        $this->login();
        $file = "{$this->dataFolder}/config.json";
        file_put_contents($file, '{}');
        chmod($file, 0600);
        $inode = fileinode($file);

        $this->postJson('/admin/config', ['invitation_org_name' => 'Example', 'admin_token' => self::TOKEN])->assertStatus(200);

        // Every request reads the file, so a new one takes its place instead of the old one being truncated and rewritten.
        clearstatcache();
        $this->assertNotSame($inode, fileinode($file));
        $this->assertSame(0600, fileperms($file) & 0777);
        $this->assertSame([], glob("{$this->dataFolder}/*.tmp"));
    }

    public function test_the_login_form_is_limited_like_rockets_forms(): void
    {
        $this->useDatabase('sqlite');

        $this->form('/admin', ['token' => str_repeat('a', 32 * 1024)])->assertStatus(413);
    }

    #[Parity('route:GET /admin/diagnostics/config')]
    public function test_support_settings_hide_what_identifies_the_server(): void
    {
        $this->useDatabase('sqlite');
        $this->changeVaultwardenEnvironment(['DOMAIN' => 'https://vault.example.com', 'SMTP_HOST' => 'smtp.example.com', 'SMTP_USERNAME' => 'user', 'SMTP_PASSWORD' => 'pw',
            'SMTP_FROM' => 'vault@example.com']);
        $this->login();

        $support = $this->getJson('/admin/diagnostics/config')->assertStatus(200)->json();
        $this->assertIsArray($support);
        $this->assertSame(array_keys($support), array_values(array_unique(array_keys($support))));
        $sorted = array_keys($support);
        sort($sorted, SORT_STRING);
        $this->assertSame($sorted, array_keys($support));
        // A URL keeps its colon and slashes.
        $this->assertSame('*****://'.str_repeat('*', 17), $support['domain']);
        $this->assertSame('****************', $support['smtp_host']);
        $this->assertSame('***', $support['smtp_password']);
        $this->assertNull($support['hibp_api_key']);
        $this->assertSame('***', $support['admin_token']);
        $this->assertSame('***', $support['push_installation_key']);
        $this->assertSame(100000, $support['password_iterations']);
    }

    #[Parity('route:POST /admin/config/backup_db')]
    public function test_the_sqlite_database_is_backed_up(): void
    {
        $this->useDatabase('sqlite');
        $this->login();

        $response = $this->postJson('/admin/config/backup_db')->assertStatus(200)->assertHeader('Content-Type', 'text/plain; charset=utf-8');
        if (preg_match("#^Backup to '(.+/db_\\d{8}_\\d{6}\\.sqlite3)' was successful$#", (string) $response->getContent(), $match) !== 1) {
            $this->fail("Unexpected answer: {$response->getContent()}");
        }
        $this->assertFileExists($match[1]);
        $this->assertStringStartsWith($this->dataFolder.'/', $match[1]);

        $this->changeVaultwardenEnvironment(['DATABASE_URL' => 'mysql://user:pass@localhost/vaultwarden']);
        $this->postJson('/admin/config/backup_db')->assertStatus(400)->assertJsonPath('message', "Can't back up current DB (Only SQLite supports this feature)");
    }

    #[Parity('route:POST /admin/invite')]
    #[Parity('route:POST /admin/users/{user_id}/invite/resend')]
    #[Parity('route:POST /admin/test/smtp')]
    #[Parity('config:INVITATION_ORG_NAME')]
    public function test_invitations(): void
    {
        $this->useDatabase('sqlite');
        $this->login();

        $invited = $this->postJson('/admin/invite', ['email' => 'Invited@Example.com'])->assertStatus(200)
            ->assertJsonPath('email', 'invited@example.com')->assertJsonPath('_status', 1)->json('id');
        $this->assertIsString($invited);
        $this->assertNotNull(Invitation::findByMail('invited@example.com'));
        $this->postJson('/admin/invite', ['email' => 'invited@example.com'])->assertStatus(409)->assertJsonPath('message', 'User already exists');
        $this->postJson('/admin/invite', ['email' => 'nope'])->assertStatus(500)
            ->assertJsonPath('message', 'Invitation email nope is not a valid email address');
        $this->postJson("/admin/users/{$invited}/invite/resend")->assertStatus(200);
        $this->postJson('/admin/test/smtp', ['email' => 'test@example.com'])->assertStatus(400)->assertJsonPath('message', 'Mail is not enabled');

        $mails = new MailTransportFake;
        $this->app->instance(Transport::class, $mails);
        $this->changeVaultwardenEnvironment(['SMTP_HOST' => 'localhost', 'SMTP_FROM' => 'vault@example.com', 'INVITATION_ORG_NAME' => 'Example Org']);
        $this->postJson('/admin/invite', ['email' => 'mailed@example.com'])->assertStatus(200);
        $this->assertSame('Join Example Org', $mails->sent[0]['subject']);
        $this->assertStringContainsString('organizationId=00000000-0000-0000-0000-000000000000', $mails->sent[0]['text']);
        $this->assertNull(Invitation::findByMail('mailed@example.com'));
        $this->postJson("/admin/users/{$invited}/invite/resend")->assertStatus(200);
        $this->assertSame('invited@example.com', $mails->sent[1]['to']);
        $this->postJson('/admin/test/smtp', ['email' => 'test@example.com'])->assertStatus(200);
        $this->assertSame('Vaultwarden SMTP Test', $mails->sent[2]['subject']);

        // A user is only saved when the invitation could be sent.
        $mails->failure = 'Mail failed';
        $this->postJson('/admin/invite', ['email' => 'unsent@example.com'])->assertStatus(500)->assertJsonPath('message', 'Mail failed');
        $this->assertNull(User::findByMail('unsent@example.com'));
    }

    #[Parity('route:POST /admin/users/{user_id}/delete')]
    #[Parity('route:DELETE /admin/users/{user_id}/sso')]
    #[Parity('route:POST /admin/users/org_type')]
    public function test_membership_events_name_the_admin(): void
    {
        $this->useDatabase('sqlite');
        $this->changeVaultwardenEnvironment(['ORG_EVENTS_ENABLED' => 'true']);
        $this->login();
        $owner = $this->user('owner@example.com');
        $member = $this->user('member@example.com');
        $org = Organization::new('2.org', 'billing@example.com', null, null);
        $org->save();
        foreach ([[$owner, Membership::TYPE_OWNER], [$member, Membership::TYPE_USER]] as [$user, $type]) {
            $membership = Membership::new($user->uuid, $org->uuid, null);
            $membership->atype = $type;
            $membership->status = Membership::STATUS_CONFIRMED;
            $membership->save();
        }

        $this->postJson('/admin/users/org_type', ['user_type' => '1', 'user_uuid' => $member->uuid, 'org_uuid' => $org->uuid])->assertStatus(200);
        $this->assertSame(Membership::TYPE_ADMIN, Membership::findByUserAndOrg($member->uuid, $org->uuid)?->atype);
        $this->deleteJson("/admin/users/{$member->uuid}/sso")->assertStatus(200);
        $this->postJson("/admin/users/{$owner->uuid}/delete")->assertStatus(400)->assertJsonPath('message', "Can't delete last owner");
        $this->postJson("/admin/users/{$member->uuid}/delete")->assertStatus(200);

        $events = Event::query()->orderBy('event_type')->get();
        $this->assertSame([Event::ORGANIZATION_USER_UPDATED, Event::ORGANIZATION_USER_UNLINKED_SSO, Event::ORGANIZATION_USER_DELETED, Event::ORGANIZATION_USER_DELETED],
            $events->pluck('event_type')->all());
        foreach ($events as $event) {
            $this->assertSame('vaultwarden-admin-00000-000000000000', $event->act_user_uuid);
            $this->assertSame(14, $event->device_type);
        }
        $this->assertNull(User::findByUuid($member->uuid));
    }

    /**
     * The agreed deviation: Vaultwarphpen, the release it mirrors and PHP's runtime.
     */
    #[Parity('route:GET /admin/diagnostics')]
    #[Parity('route:GET /admin/diagnostics/http')]
    public function test_diagnostics_name_vaultwarphpen(): void
    {
        $this->useDatabase('sqlite');
        // No requests leave the test, and the web vault installed for the client tests stays out of it.
        $this->changeVaultwardenEnvironment(['HTTP_REQUEST_BLOCK_REGEX' => '.*', 'WEB_VAULT_FOLDER' => sys_get_temp_dir().'/no-web-vault/']);
        $this->login();

        $page = $this->get('/admin/diagnostics', ['X-Forwarded-For' => '192.0.2.1'])->assertStatus(200);
        if (preg_match('#id="diagnostics_json">(.*?)</script>#', (string) $page->getContent(), $match) !== 1) {
            $this->fail('The page has no diagnostics data.');
        }
        $data = json_decode($match[1], true);
        $this->assertIsArray($data);
        $this->assertSame('Vaultwarphpen '.Release::installed().' (Vaultwarden 1.37.5)', $data['current_release']);
        $this->assertSame(['-', '-', '-'], [$data['latest_release'], $data['latest_commit'], $data['latest_web_release']]);
        $this->assertFalse($data['has_http_access']);
        $this->assertSame('Unable to fetch NTP time.', $data['ntp_time']);
        $this->assertIsString($data['host_arch']);
        $this->assertStringContainsString('(PHP '.PHP_VERSION.', ', $data['host_arch']);
        $this->assertSame(['SQLite', 'X-Forwarded-For', false, 'Version file missing', 'http://localhost/admin/diagnostics'],
            [$data['db_type'], $data['ip_header_name'], $data['ip_header_match'], $data['active_web_release'], $data['admin_url']]);
        $sorted = array_keys($data);
        sort($sorted, SORT_STRING);
        $this->assertSame($sorted, array_keys($data));

        $this->get('/admin/diagnostics/http?code=403')->assertStatus(403)->assertJsonPath('message', 'Testing error 403 response');
        $this->get('/admin/diagnostics/http?code=1000')->assertStatus(400)->assertJsonPath('message', 'Testing error 1000 response');
        $this->get('/admin/diagnostics/http?code=%2B299')->assertStatus(400);
        $this->get('/admin/diagnostics/http?code=70000')->assertStatus(404);
        $this->get('/admin/diagnostics/http')->assertStatus(404);
    }

    public function test_web_vault_versions_compare_like_semver(): void
    {
        // The cases of admin.rs.
        $this->assertSame(-1, AdminController::webVaultCompare('2025.12.0', '2025.12.1'));
        $this->assertSame(0, AdminController::webVaultCompare('2025.12.1', '2025.12.1'));
        $this->assertSame(1, AdminController::webVaultCompare('2025.12.2', '2025.12.1'));
        $this->assertSame(-1, AdminController::webVaultCompare('2025.12.0+build.1', '2025.12.1'));
        $this->assertSame(-1, AdminController::webVaultCompare('2025.12.1', '2025.12.1+build.1'));
        $this->assertSame(-1, AdminController::webVaultCompare('2025.12.0+build.1', '2025.12.1+build.1'));
        $this->assertSame(-1, AdminController::webVaultCompare('2025.12.1+build.1', '2025.12.1+build.2'));
        $this->assertSame(0, AdminController::webVaultCompare('2025.12.1+build.1', '2025.12.1+build.1'));
        $this->assertSame(0, AdminController::webVaultCompare('2025.12.2+build.2', '2025.12.2+build.2'));
        $this->assertSame(1, AdminController::webVaultCompare('2025.12.1+build.1', '2025.12.1'));
        $this->assertSame(1, AdminController::webVaultCompare('2025.12.2', '2025.12.1+build.1'));
        $this->assertSame(1, AdminController::webVaultCompare('2025.12.2+build.1', '2025.12.1+build.1'));
        $this->assertSame(1, AdminController::webVaultCompare('2025.12.1+build.3', '2025.12.1+build.2'));
        // Versions that do not parse count as 2025.1.1; pre-releases come before their release.
        $this->assertSame(0, AdminController::webVaultCompare('Version file missing', '-'));
        $this->assertSame(-1, AdminController::webVaultCompare('2026.1.0-beta.2', '2026.1.0'));
        $this->assertSame(1, AdminController::webVaultCompare('2026.1.0-beta.11', '2026.1.0-beta.2'));
    }

    #[Parity('route:GET /vw_static/{filename}')]
    public function test_static_files_are_cached_by_etag(): void
    {
        $etag = '"'.hash_file('sha256', resource_path('vaultwarden/static/scripts/admin.js')).'"';

        $this->get('/vw_static/admin.js')->assertStatus(200)->assertHeader('Content-Type', 'text/javascript')
            ->assertHeader('Etag', $etag)->assertHeader('Cache-Control', 'no-cache, public');
        $this->get('/vw_static/admin.js', ['If-None-Match' => "\"x\", W/{$etag}"])->assertStatus(304)
            ->assertHeader('Content-Type', 'text/javascript')->assertHeader('Etag', $etag)->assertContent('');
        $this->get('/vw_static/hibp.png')->assertStatus(200)->assertHeader('Content-Type', 'image/png');
        $this->get('/vw_static/bootstrap.css')->assertStatus(200)->assertHeader('Content-Type', 'text/css; charset=utf-8');
        // The web vault's catch-all refuses hidden files: its guard forwards, and no route is left.
        $this->get('/vw_static/../.env')->assertStatus(422);
        $this->get('/vw_static/admin')->assertStatus(400)->assertJsonPath('message', 'Static file not found: admin');
        $this->get("/vw_static/o'neil%09%22.js")->assertStatus(400)->assertJsonPath('message', 'Static file not found: o\\\'neil\\t\\".js');
    }

    /**
     * A form POST with its body, as a browser sends it.
     *
     * @param  array<string, string>  $fields
     * @param  array<string, string>  $headers
     * @return TestResponse<Response>
     */
    private function form(string $uri, array $fields, array $headers = []): TestResponse
    {
        return $this->call('POST', $uri, server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded', ...$this->transformHeadersToServerVars($headers)],
            content: http_build_query($fields));
    }

    /**
     * Log in with the token, keeping the session cookie for the next requests.
     */
    private function login(): void
    {
        $cookie = $this->sessionCookie($this->form('/admin', ['token' => self::TOKEN])->assertStatus(200));
        $this->withUnencryptedCookie(AdminToken::COOKIE_NAME, (string) $cookie->getValue())->withCredentials();
    }

    /**
     * @param  TestResponse<Response>  $response
     */
    private function sessionCookie(TestResponse $response): Cookie
    {
        foreach ($response->headers->getCookies() as $cookie) {
            if ($cookie->getName() === AdminToken::COOKIE_NAME) {
                return $cookie;
            }
        }

        $this->fail('No session cookie.');
    }

    private function user(string $email): User
    {
        $user = User::new($email);
        $user->setPassword('hash', 'user-key', false, null);
        $user->save();

        return $user;
    }
}
