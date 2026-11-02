<?php

namespace Tests\Differential;

use App\Http\Controllers\TwoFactor\AuthenticatorController;
use App\Support\Base32;
use Tests\Attributes\Parity;

/**
 * The admin panel. The default pair has a plain ADMIN_TOKEN and no mail, the
 * mail pair an Argon2 PHC string; the pair with groups and events has none,
 * so its panel is disabled (.github/scripts/differential.sh).
 *
 * Pages are compared as HTML after the values that differ by nature are
 * replaced: each server's data folder, local times, other tests' rows.
 */
class AdminTest extends DifferentialTestCase
{
    /**
     * ADMIN_TOKEN of the default pair.
     */
    public const string TOKEN = 'differential-admin-token';

    /**
     * The token whose Argon2id PHC string is ADMIN_TOKEN of the mail pair.
     */
    public const string MAIL_TOKEN = 'differential-argon2-token';

    #[Parity('route:GET /admin#admin_page')]
    #[Parity('route:GET /admin#admin_page_login')]
    #[Parity('route:POST /admin')]
    #[Parity('route:GET /admin/logout')]
    #[Parity('template:admin/base')]
    #[Parity('template:admin/login')]
    #[Parity('template:admin/settings')]
    #[Parity('config:ADMIN_TOKEN')]
    #[Parity('config:ADMIN_SESSION_LIFETIME')]
    public function test_login_and_logout(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            $steps = [];
            $steps['panel without session'] = self::page($server->send('GET', '/admin'));
            $steps['page without session'] = self::page($server->send('GET', '/admin/users/overview'));
            $steps['nested page without session'] = self::page($server->send('GET', '/admin/users/overview/more?x=1'));
            $steps['JSON without session'] = $server->send('GET', '/admin/users', ['Accept' => 'application/json']);
            $steps['action without session'] = $server->json('POST', '/admin/users/update_revision', []);
            $steps['action without its content type'] = self::page($server->send('POST', '/admin/users/update_revision'));
            $steps['unknown page'] = self::page($server->send('GET', '/admin/nope'));

            $steps['login with a wrong token'] = self::page($server->form('/admin', ['token' => 'wrong']));
            $steps['login with a wrong token and a page'] = self::page($server->form('/admin', ['token' => 'wrong', 'redirect' => '/users/overview']));
            $steps['login without token'] = self::page($server->form('/admin', ['redirect' => '/users/overview']));
            $steps['login with JSON'] = self::page($server->json('POST', '/admin', ['token' => self::TOKEN]));
            $steps['login with spaces around the token'] = self::cookie($login = $server->form('/admin', ['token' => ' '.self::TOKEN.' ', 'redirect' => '/users/overview']));
            $steps['login and go to a page'] = $login->withBody('');
            $steps['login'] = self::page($login = $server->form('/admin', ['token' => self::TOKEN]));
            $steps['session cookie'] = self::cookie($login);
            $session = self::session($login);

            $steps['panel'] = self::page($server->send('GET', '/admin', $session));
            $steps['panel with an expired session'] = self::page($server->send('GET', '/admin', ['Cookie' => 'VW_ADMIN='.$this->adminToken(-3600)]));
            $steps['cookie of an expired session'] = self::cookie($server->send('GET', '/admin/diagnostics', ['Cookie' => 'VW_ADMIN='.$this->adminToken(-3600)]));
            $steps['panel with a token of another kind'] = self::page($server->send('GET', '/admin', ['Cookie' => 'VW_ADMIN='.$this->signedToken('delete', [
                'nbf' => time(), 'exp' => time() + 600, 'sub' => 'admin_panel'])]));
            $steps['panel with a signed session'] = self::page($server->send('GET', '/admin', ['Cookie' => 'VW_ADMIN='.$this->adminToken(600)]));

            $steps['logout'] = self::cookie($server->send('GET', '/admin/logout', $session));
            $steps['logout without session'] = self::cookie($server->send('GET', '/admin/logout'));

            return $steps;
        });
    }

    /**
     * A session started at one implementation works at the other.
     */
    #[Parity('route:GET /admin#admin_page')]
    public function test_sessions_are_shared(): void
    {
        $reference = (string) getenv('VW_REFERENCE_URL');
        $subject = (string) getenv('VW_SUBJECT_URL');
        $fromReference = self::session(self::send($reference, 'POST', '/admin', ['Content-Type' => 'application/x-www-form-urlencoded'], 'token='.self::TOKEN));
        $fromSubject = self::session(self::send($subject, 'POST', '/admin', ['Content-Type' => 'application/x-www-form-urlencoded'], 'token='.self::TOKEN));

        $this->assertSameExchange(
            self::page(self::send($reference, 'GET', '/admin/diagnostics/config', ['Accept' => 'application/json', ...$fromSubject])),
            self::page(self::send($subject, 'GET', '/admin/diagnostics/config', ['Accept' => 'application/json', ...$fromReference])),
            'a session of the other implementation',
        );
    }

    #[Parity('route:GET /admin')]
    public function test_disabled_panel(): void
    {
        $this->assertSameFlowsOn((string) getenv('VW_FEATURES_REFERENCE_URL'), (string) getenv('VW_FEATURES_SUBJECT_URL'), static fn (Server $server): array => [
            'panel' => $server->send('GET', '/admin'),
            'page' => self::page($server->send('GET', '/admin/users/overview')),
            'login' => self::page($server->form('/admin', ['token' => self::TOKEN])),
            'logout' => self::page($server->send('GET', '/admin/logout')),
        ]);
    }

    #[Parity('route:POST /admin/config')]
    #[Parity('route:POST /admin/config/delete')]
    #[Parity('route:POST /admin/config/backup_db')]
    #[Parity('route:GET /admin/diagnostics/config')]
    #[Parity('template:admin/settings')]
    public function test_settings(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            $session = self::login($server);
            $json = ['Content-Type' => 'application/json', ...$session];
            $steps = [];
            try {
                $steps['save'] = $server->json('POST', '/admin/config', [
                    'icon_cache_ttl' => 1000,
                    'invitation_org_name' => 'Differential & <Admin>',
                    'admin_token' => self::TOKEN,
                    // Not editable: dropped.
                    'data_folder' => '/elsewhere',
                    'unknown' => 1,
                    'sends_allowed' => null,
                ], $session);
                $steps['panel with the saved settings'] = self::page($server->send('GET', '/admin', $session));
                $steps['support settings'] = self::page($server->send('GET', '/admin/diagnostics/config', ['Accept' => 'application/json', ...$session]));
                $steps['save an invalid setting'] = $server->json('POST', '/admin/config', ['password_iterations' => 1000], $session);
                $steps['save a number as text'] = $server->json('POST', '/admin/config', ['icon_cache_ttl' => '1000'], $session);
                $steps['save a number out of range'] = $server->json('POST', '/admin/config', ['icon_download_timeout' => 70000], $session);
                $steps['save a list'] = $server->json('POST', '/admin/config', [1, 2], $session);
                $steps['save invalid JSON'] = $server->send('POST', '/admin/config', $json, '{');
                $steps['panel after the failures'] = self::page($server->send('GET', '/admin', $session));
            } finally {
                $steps['reset'] = $server->send('POST', '/admin/config/delete', $json);
            }
            $steps['reset again'] = $server->send('POST', '/admin/config/delete', $json);
            $steps['panel with the defaults'] = self::page($server->send('GET', '/admin', $session));
            $steps['support settings without JSON'] = self::page($server->send('GET', '/admin/diagnostics/config', ['Accept' => 'text/html', ...$session]));
            $steps['backup'] = self::page($server->send('POST', '/admin/config/backup_db', $json));

            return $steps;
        });
    }

    #[Parity('route:GET /admin/users')]
    #[Parity('route:GET /admin/users/{user_id}')]
    #[Parity('route:GET /admin/users/by-mail/{mail}')]
    #[Parity('route:GET /admin/users/overview')]
    #[Parity('route:POST /admin/invite')]
    #[Parity('route:POST /admin/users/{user_id}/delete')]
    #[Parity('route:DELETE /admin/users/{user_id}/sso')]
    #[Parity('route:POST /admin/users/{user_id}/deauth')]
    #[Parity('route:POST /admin/users/{user_id}/disable')]
    #[Parity('route:POST /admin/users/{user_id}/enable')]
    #[Parity('route:POST /admin/users/{user_id}/remove-2fa')]
    #[Parity('route:POST /admin/users/{user_id}/invite/resend')]
    #[Parity('route:POST /admin/users/update_revision')]
    #[Parity('template:admin/users')]
    public function test_users(): void
    {
        $emails = ['admin-user@example.com', 'admin-other@example.com', 'admin-invited@example.com'];
        $this->assertSameFlows(function (Server $server) use ($emails): array {
            [$auth, $userId] = CipherTest::session($server, $emails[0]);
            [, $otherId] = CipherTest::session($server, $emails[1]);
            CipherTest::note($server, $auth, $userId, '2.note');
            $session = self::login($server);
            $json = ['Content-Type' => 'application/json', ...$session];
            $steps = [];

            $steps['invite'] = $server->json('POST', '/admin/invite', ['email' => 'Admin-Invited@example.com'], $session);
            $invitedId = $steps['invite']->jsonString('id');
            $steps['invite again'] = $server->json('POST', '/admin/invite', ['email' => $emails[2]], $session);
            $steps['invite an invalid address'] = $server->json('POST', '/admin/invite', ['email' => 'not-an-address'], $session);
            $steps['invite without address'] = $server->json('POST', '/admin/invite', [], $session);
            $steps['resend the invitation'] = $server->send('POST', "/admin/users/{$invitedId}/invite/resend", $json);
            $steps['resend to a registered user'] = $server->send('POST', "/admin/users/{$userId}/invite/resend", $json);
            $steps['resend to nobody'] = $server->send('POST', '/admin/users/00000000-0000-0000-0000-000000000001/invite/resend', $json);
            $steps['test mail without mail'] = $server->json('POST', '/admin/test/smtp', ['email' => $emails[0]], $session);

            $steps['users'] = self::users($server->send('GET', '/admin/users', $session), $emails);
            $steps['user'] = self::page($server->send('GET', "/admin/users/{$userId}", $session));
            $steps['invited user'] = self::page($server->send('GET', "/admin/users/{$invitedId}", $session));
            $steps['unknown user'] = $server->send('GET', '/admin/users/00000000-0000-0000-0000-000000000001', $session);
            $steps['user with an invalid id'] = self::page($server->send('GET', '/admin/users/nope', $session));
            $steps['user by mail'] = self::page($server->send('GET', '/admin/users/by-mail/ADMIN-USER@example.com', $session));
            $steps['unknown mail'] = $server->send('GET', '/admin/users/by-mail/nobody@example.com', $session);
            $steps['overview'] = self::page($server->send('GET', '/admin/users/overview', $session), $emails);

            $steps['disable'] = $server->send('POST', "/admin/users/{$userId}/disable", $json);
            $steps['login when disabled'] = $server->form('/identity/connect/token', LoginTest::loginFields($emails[0]));
            $steps['sync when disabled'] = $server->send('GET', '/api/sync', $auth);
            $steps['overview with the user disabled'] = self::page($server->send('GET', '/admin/users/overview', $session), $emails);
            $steps['enable'] = $server->send('POST', "/admin/users/{$userId}/enable", $json);
            $login = $server->form('/identity/connect/token', LoginTest::loginFields($emails[0]));
            $steps['login when enabled'] = $login;
            $steps['deauthorize'] = $server->send('POST', "/admin/users/{$userId}/deauth", $json);
            $steps['refresh after deauthorizing'] = $server->form('/identity/connect/token', [
                'grant_type' => 'refresh_token', 'refresh_token' => $login->jsonString('refresh_token'), 'client_id' => 'cli']);
            $steps['deauthorize without its content type'] = self::page($server->send('POST', "/admin/users/{$userId}/deauth", $session));
            $steps['deauthorize nobody'] = $server->send('POST', '/admin/users/00000000-0000-0000-0000-000000000001/deauth', $json);
            $steps['deauthorize an invalid id'] = self::page($server->send('POST', '/admin/users/nope/deauth', $json));

            $auth = FolderTest::session($server, $emails[0]);
            $steps['set up an authenticator'] = $this->enableAuthenticator($server, $auth);
            $steps['users with two-factor login'] = self::users($server->send('GET', '/admin/users', $session), $emails);
            $steps['remove two-factor login'] = $server->send('POST', "/admin/users/{$userId}/remove-2fa", $json);
            $steps['two-factor methods afterwards'] = $server->send('GET', '/api/two-factor', $auth);
            $steps['remove the SSO link'] = $server->send('DELETE', "/admin/users/{$userId}/sso", $json);
            $steps['update revisions'] = $server->send('POST', '/admin/users/update_revision', $json);

            $steps['delete'] = $server->send('POST', "/admin/users/{$otherId}/delete", $json);
            $steps['delete the invited'] = $server->send('POST', "/admin/users/{$invitedId}/delete", $json);
            $steps['delete again'] = $server->send('POST', "/admin/users/{$otherId}/delete", $json);
            $steps['users at last'] = self::users($server->send('GET', '/admin/users', $session), $emails);

            return $steps;
        });
    }

    #[Parity('route:POST /admin/users/org_type')]
    #[Parity('route:GET /admin/organizations/overview')]
    #[Parity('route:POST /admin/organizations/{org_id}/delete')]
    #[Parity('route:POST /admin/users/{user_id}/delete')]
    #[Parity('template:admin/organizations')]
    public function test_organizations(): void
    {
        $emails = ['admin-owner@example.com', 'admin-member@example.com'];
        $this->assertSameFlows(function (Server $server) use ($emails): array {
            [$owner, $ownerId] = CipherTest::session($server, $emails[0]);
            [, $memberId] = CipherTest::session($server, $emails[1]);
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            OrganizationTest::addMember($server, $owner, $org, $emails[1]);
            $session = self::login($server);
            $type = static fn (string $user, mixed $type): array => ['user_type' => $type, 'user_uuid' => $user, 'org_uuid' => $org];
            $steps = [];

            $steps['overview'] = self::page($server->send('GET', '/admin/organizations/overview', $session), [$org]);
            $steps['users with the organization'] = self::page($server->send('GET', '/admin/users/overview', $session), $emails);
            $steps['make admin'] = $server->json('POST', '/admin/users/org_type', $type($memberId, 1), $session);
            $steps['make manager by name'] = $server->json('POST', '/admin/users/org_type', $type($memberId, 'Manager'), $session);
            $steps['make custom'] = $server->json('POST', '/admin/users/org_type', $type($memberId, '4'), $session);
            $steps['invalid type'] = $server->json('POST', '/admin/users/org_type', $type($memberId, 9), $session);
            $steps['type as a list'] = $server->json('POST', '/admin/users/org_type', $type($memberId, [1]), $session);
            $steps['demote the last owner'] = $server->json('POST', '/admin/users/org_type', $type($ownerId, 2), $session);
            $steps['not a member'] = $server->json('POST', '/admin/users/org_type', ['user_type' => 2, 'user_uuid' => $memberId, 'org_uuid' => $memberId], $session);
            $steps['without organization'] = $server->json('POST', '/admin/users/org_type', ['user_type' => 2, 'user_uuid' => $memberId], $session);
            $steps['make owner'] = $server->json('POST', '/admin/users/org_type', $type($memberId, 0), $session);
            $steps['demote the first owner'] = $server->json('POST', '/admin/users/org_type', $type($ownerId, 2), $session);
            $steps['members'] = $server->send('GET', "/api/organizations/{$org}/users", $owner);

            $steps['delete a member'] = $server->send('POST', "/admin/users/{$memberId}/delete", ['Content-Type' => 'application/json', ...$session]);
            $steps['delete the unknown'] = $server->send('POST', '/admin/organizations/00000000-0000-0000-0000-000000000001/delete', ['Content-Type' => 'application/json', ...$session]);
            $steps['delete'] = $server->send('POST', "/admin/organizations/{$org}/delete", ['Content-Type' => 'application/json', ...$session]);
            $steps['overview afterwards'] = self::page($server->send('GET', '/admin/organizations/overview', $session), [$org]);
            $steps['delete the owner'] = $server->send('POST', "/admin/users/{$ownerId}/delete", ['Content-Type' => 'application/json', ...$session]);

            return $steps;
        });
    }

    /**
     * The diagnostics name Vaultwarphpen and check its own repository, so the
     * page is compared by its structure: the same elements and data keys.
     */
    #[Parity('route:GET /admin/diagnostics')]
    #[Parity('route:GET /admin/diagnostics/http')]
    #[Parity('template:admin/diagnostics')]
    public function test_diagnostics(): void
    {
        $this->assertSameFlows(function (Server $server): array {
            $session = self::login($server);
            $steps = [];

            $page = $server->send('GET', '/admin/diagnostics', $session);
            $steps['page'] = $page->withBody(self::structure($page->body));
            foreach (['400', '401', '403', '404', '299', '200', '1000', '+404', 'x', ''] as $code) {
                $steps["status {$code}"] = self::page($server->send('GET', "/admin/diagnostics/http?code={$code}", $session));
            }
            $steps['status missing'] = self::page($server->send('GET', '/admin/diagnostics/http', $session));
            $steps['status without session'] = self::page($server->send('GET', '/admin/diagnostics/http?code=404'));

            return $steps;
        });
    }

    #[Parity('route:GET /vw_static/{filename}')]
    #[Parity('asset:scripts/*')]
    #[Parity('asset:images/*')]
    public function test_static_files(): void
    {
        $files = ['404.png', 'mail-github.png', 'logo-gray.png', 'error-x.svg', 'hibp.png', 'vaultwarden-icon.png', 'vaultwarden-favicon.png',
            '404.css', 'admin.css', 'admin.js', 'admin_settings.js', 'admin_users.js', 'admin_organizations.js', 'admin_diagnostics.js',
            'bootstrap.css', 'bootstrap.bundle.js', 'jdenticon-3.3.0.js', 'datatables.js', 'datatables.css'];

        $this->assertSameFlows(function (Server $server) use ($files): array {
            $steps = [];
            foreach ($files as $file) {
                $steps[$file] = self::withEtag($response = $server->send('GET', "/vw_static/{$file}"));
                $etag = (string) $response->header('Etag');
                $steps["{$file} unchanged"] = self::withEtag($server->send('GET', "/vw_static/{$file}", ['If-None-Match' => "\"other\", W/{$etag}"]));
            }
            $steps['changed'] = self::withEtag($server->send('GET', '/vw_static/admin.js', ['If-None-Match' => '"other"']));
            $steps['head'] = self::withEtag($server->send('HEAD', '/vw_static/admin.css'));
            $steps['unknown'] = $server->send('GET', '/vw_static/nope.js');
            $steps['encoded'] = $server->send('GET', '/vw_static/admin%2Ejs');
            // Vaultwarden 6ed6921c: the name is escaped.
            $steps['unknown with a quote'] = $server->send('GET', "/vw_static/o'neil%09%22.js");

            return $steps;
        });
    }

    #[Parity('route:POST /admin/invite')]
    #[Parity('route:POST /admin/users/{user_id}/invite/resend')]
    #[Parity('route:POST /admin/test/smtp')]
    #[Parity('route:POST /admin/users/{user_id}/remove-2fa')]
    #[Parity('template:email/smtp_test*')]
    #[Parity('config:INVITATION_ORG_NAME')]
    public function test_mail(): void
    {
        $this->assertSameMailFlows(function (Server $server): array {
            $session = self::login($server, self::MAIL_TOKEN);
            $json = ['Content-Type' => 'application/json', ...$session];
            $steps = [];

            $steps['login with a wrong token'] = self::page($server->form('/admin', ['token' => 'differential']));
            $steps['invite'] = $server->json('POST', '/admin/invite', ['email' => 'admin-mail-invited@example.com'], $session);
            $steps['invitation mail'] = $server->mail('admin-mail-invited@example.com')->exchange();
            $invitedId = $steps['invite']->jsonString('id');
            $steps['resend'] = $server->send('POST', "/admin/users/{$invitedId}/invite/resend", $json);
            $steps['resent mail'] = $server->mail('admin-mail-invited@example.com')->exchange();
            $steps['test mail'] = $server->json('POST', '/admin/test/smtp', ['email' => 'admin-mail-test@example.com'], $session);
            $steps['the test mail'] = $server->mail('admin-mail-test@example.com')->exchange();

            // Removing two-factor login revokes the member of an organization that requires it.
            [$owner] = CipherTest::session($server, 'admin-mail-owner@example.com');
            [$member, $memberId] = CipherTest::session($server, 'admin-mail-member@example.com');
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $this->enableAuthenticator($server, $member);
            $users = "/api/organizations/{$org}/users";
            $server->json('POST', "{$users}/invite", ['emails' => ['admin-mail-member@example.com'], 'groups' => [], 'type' => 2], $owner);
            $membership = OrganizationTest::memberIds($server->send('GET', $users, $owner))['admin-mail-member@example.com'];
            $server->json('POST', "{$users}/{$membership}/accept", ['token' => $server->mailedToken('admin-mail-member@example.com')], $member);
            $server->json('POST', "{$users}/{$membership}/confirm", ['key' => '4.member-key'], $owner);
            $server->json('PUT', "/api/organizations/{$org}/policies/0", ['policy' => ['enabled' => true, 'data' => null]], $owner);
            $steps['remove two-factor login'] = $server->send('POST', "/admin/users/{$memberId}/remove-2fa", $json);
            $steps['two-factor mail'] = $server->mail('admin-mail-member@example.com')->exchange();
            $steps['members'] = $server->send('GET', "/api/organizations/{$org}/users", $owner);
            $steps['the organization in the overview'] = self::page($server->send('GET', '/admin/organizations/overview', $session), [$org]);

            return $steps;
        });
    }

    /**
     * POST /api/two-factor/authenticator with a fresh key.
     *
     * @param  array<string, string>  $auth
     */
    private function enableAuthenticator(Server $server, array $auth): Exchange
    {
        $setup = $server->json('POST', '/api/two-factor/get-authenticator', ['masterPasswordHash' => 'client-hash'], $auth);
        $key = $setup->jsonString('authenticator.key');

        return $server->json('POST', '/api/two-factor/authenticator', ['key' => $key, 'userVerificationToken' => $setup->jsonString('userVerificationToken'),
            'token' => AuthenticatorController::totp(Base32::decode($key) ?? '', time())], $auth);
    }

    /**
     * A session token as the default pair issues it, valid for the seconds given.
     */
    private function adminToken(int $seconds): string
    {
        return $this->signedToken('admin', ['nbf' => time() - 7200, 'exp' => time() + $seconds, 'sub' => 'admin_panel']);
    }

    /**
     * @return array<string, string> The Cookie header of the session
     */
    public static function login(Server $server, string $token = self::TOKEN): array
    {
        return self::session($server->form('/admin', ['token' => $token]));
    }

    /**
     * @return array<string, string>
     */
    private static function session(Exchange $login): array
    {
        if (preg_match('/VW_ADMIN=([^;]+)/', (string) $login->header('Set-Cookie'), $match) !== 1) {
            throw new \RuntimeException("No session in the {$login->status} response: {$login->body}");
        }

        return ['Cookie' => "VW_ADMIN={$match[1]}"];
    }

    /**
     * The cookie a response sets, as a list of its attributes; the expiry
     * date is left out, it is computed at a different second.
     */
    private static function cookie(Exchange $exchange): Exchange
    {
        $header = $exchange->header('Set-Cookie');
        $cookie = null;
        if ($header !== null) {
            $parts = array_map(trim(...), explode(';', $header));
            $cookie = [array_shift($parts)];
            foreach ($parts as $part) {
                if (! str_starts_with(strtolower($part), 'expires=')) {
                    $cookie[] = strtolower($part);
                }
            }
            sort($cookie);
        }

        return new Exchange($exchange->status, $exchange->headers, (string) json_encode(['cookie' => $cookie, 'location' => $exchange->header('Location')]));
    }

    /**
     * A page or response without what differs by nature: data folders, local
     * times, sizes of masked values and, when given, the rows of other tests.
     *
     * @param  list<string>|null  $only  Rows of a table are kept only when they contain one of these
     */
    private static function page(Exchange $exchange, ?array $only = null): Exchange
    {
        $body = (string) preg_replace([
            '#(?:/[^/"\'\s<>,]+)+?/(?:mail-|features-)?(?:reference|subject)(?=[/"\'<\s,]|$)#',
            '/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (?:[+-]\d{2}:\d{2}|[A-Z]{3,4})/',
            '/\*{4,}/',
            '/db_\d{8}_\d{6}\.sqlite3/',
        ], ['<data folder>', '<local time>', '<masked>', 'db_<time>.sqlite3'], $exchange->body);

        if ($only !== null) {
            $body = (string) preg_replace_callback('#<tr>.*?</tr>#s', static fn (array $row): string => array_any(
                $only,
                static fn (string $needle): bool => str_contains($row[0], $needle),
            ) ? $row[0] : '', $body);
        }

        return $exchange->withBody($body);
    }

    /**
     * The users of the test from a list of all users.
     *
     * @param  list<string>  $emails
     */
    private static function users(Exchange $exchange, array $emails): Exchange
    {
        $users = json_decode($exchange->body, true);
        if (! is_array($users)) {
            return $exchange;
        }
        $users = array_values(array_filter($users, static fn (mixed $user): bool => is_array($user) && in_array($user['email'] ?? null, $emails, true)));

        return self::page($exchange->withBody((string) json_encode($users, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)));
    }

    /**
     * The tags, ids and data keys of the diagnostics page.
     */
    private static function structure(string $html): string
    {
        preg_match_all('/<(\w+)([^>]*)>/', $html, $tags, PREG_SET_ORDER);
        preg_match('#id="diagnostics_json">(.*?)</script>#s', $html, $json);
        $data = json_decode($json[1] ?? '', true);

        return (string) json_encode([
            'elements' => array_map(static fn (array $tag): string => $tag[1].(preg_match('/\sid="([^"]*)"/', $tag[2], $id) === 1 ? "#{$id[1]}" : ''), $tags),
            'data' => is_array($data) ? array_map(get_debug_type(...), $data) : null,
        ], JSON_PRETTY_PRINT);
    }

    /**
     * The ETag is compared as well, which is the SHA-256 of the file.
     */
    private static function withEtag(Exchange $exchange): Exchange
    {
        return $exchange->withBody(json_encode(['etag' => $exchange->header('Etag'), 'sha256' => hash('sha256', $exchange->body)]) ?: '');
    }
}
