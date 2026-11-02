<?php

namespace App\Http\Controllers;

use App\Auth\AdminToken;
use App\Auth\ClientIp;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\Secure;
use App\Config\Config;
use App\Config\ConfigBuilder;
use App\Config\ConfigException;
use App\Config\FeatureFlags;
use App\Database\DatabaseUrl;
use App\Http\Accept;
use App\Http\ApiError;
use App\Http\Data\Body;
use App\Http\Data\NumberOrString;
use App\Http\Data\Query;
use App\Http\EmptyResponse;
use App\Http\HttpStatus;
use App\Http\Json;
use App\Http\Redirect;
use App\Http\RocketCookie;
use App\Mail\Mail;
use App\Models\Attachment;
use App\Models\Cipher;
use App\Models\Device;
use App\Models\Event;
use App\Models\Group;
use App\Models\Invitation;
use App\Models\Membership;
use App\Models\Organization;
use App\Models\OrgCollection;
use App\Models\OrgPolicy;
use App\Models\SsoUser;
use App\Models\TwoFactor;
use App\Models\User;
use App\Notifications\Notify;
use App\Support\Dates;
use App\Support\HttpClient;
use App\Support\LocalTimeZone;
use App\Support\Push;
use App\Support\RateLimiter;
use App\Support\Release;
use App\Support\SemVer;
use App\Support\Uuid;
use App\Support\WebVault;
use App\Templates\TemplateRenderer;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use stdClass;
use Throwable;

/**
 * src/api/admin.rs: the admin panel, mounted at /admin below DOMAIN's path.
 *
 * Deviation, like the `server` object of /api/config: the diagnostics name
 * Vaultwarphpen with the Vaultwarden release it mirrors, look for newer
 * versions in Vaultwarphpen's repository, and show PHP's runtime instead of
 * Rust's.
 */
final readonly class AdminController
{
    private const string BASE_TEMPLATE = 'admin/base';

    private const string ADMIN_PATH = '/admin';

    /**
     * The acting user of the events the admin panel causes.
     */
    private const string ACTING_ADMIN_USER = 'vaultwarden-admin-00000-000000000000';

    public const string FAKE_ADMIN_UUID = '00000000-0000-0000-0000-000000000000';

    /**
     * sso::FAKE_SSO_IDENTIFIER
     */
    private const string FAKE_SSO_IDENTIFIER = '00000000-01DC-01DC-01DC-000000000000';

    /**
     * The device type of the events: UnknownBrowser.
     */
    private const int DEVICE_TYPE = 14;

    /**
     * The statuses Rocket knows (rocket::http::Status).
     */
    private const array ROCKET_STATUSES = [100, 101, 102, 103, 200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303, 304,
        305, 307, 308, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424,
        426, 428, 429, 431, 451, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511];

    /**
     * get_release_info is cached for ten minutes: GitHub allows 60 requests an hour.
     */
    private const int RELEASE_INFO_TTL = 600;

    public function __construct(
        private Config $config,
        private TemplateRenderer $templates,
        private Jwt $jwt,
        private RateLimiter $rateLimiter,
        private DatabaseManager $databases,
        private Repository $cache,
        private Notify $nt,
    ) {}

    /**
     * Whether the admin routes are mounted: with a token, or without one on
     * purpose. Otherwise only admin_disabled answers.
     */
    public static function enabled(Config $config): bool
    {
        return $config->bool('disable_admin_token') || $config->isAdminTokenSet();
    }

    /**
     * GET /admin without a token.
     */
    public function adminDisabled(): Response
    {
        return new Response("The admin panel is disabled, please configure the 'ADMIN_TOKEN' variable to enable it", 200, [
            'Content-Type' => 'text/plain; charset=utf-8',
        ]);
    }

    /**
     * The admin_login catcher for 401s below /admin: the login page, which
     * leads back to the requested page, or a JSON error for JSON requests.
     */
    public function adminLogin(Request $request): Response
    {
        if (Accept::format($request) === 'application/json') {
            return ApiError::message('Authorization failed.', 401)->toResponse();
        }

        return $this->renderAdminLogin(null, $this->requestedPage($request), 401);
    }

    /**
     * POST /admin: log in with the token; the session is a token in a cookie.
     *
     * @throws HttpStatus
     */
    public function postAdminLogin(Request $request): Response
    {
        $this->requireFormat($request, 'application/x-www-form-urlencoded');
        $form = Body::form($request);
        if (count($form['token'] ?? []) !== 1) {
            throw new HttpStatus(422, 'The form needs one token.');
        }
        $token = $form['token'][0];
        $redirect = Body::optionalFormField($form, ['redirect']);
        $ip = ClientIp::resolve($request, $this->config);

        try {
            $this->rateLimiter->check('admin', $ip);
        } catch (ApiError) {
            return $this->renderAdminLogin('Too many requests, try again later.', $redirect, 429);
        }

        if (! $this->validateToken($token)) {
            logger()->error("Invalid admin token. IP: {$ip}");

            return $this->renderAdminLogin('Invalid admin token, please try again.', $redirect, 401);
        }

        $now = time();
        $lifetime = $this->config->int('admin_session_lifetime') * 60;
        // BasicJwtClaims
        $jwt = $this->jwt->encode([
            'nbf' => $now,
            'exp' => $now + $lifetime,
            'iss' => $this->jwt->issuer(JwtIssuer::Admin),
            'sub' => 'admin_panel',
        ]);
        $cookie = RocketCookie::session(AdminToken::COOKIE_NAME, $jwt, $this->adminPath(), $lifetime, $this->isSecure($request));

        $response = $redirect === null ? $this->renderAdminPage() : new Redirect($this->adminPath().$redirect);
        $response->headers->setCookie($cookie);

        return $response;
    }

    /**
     * GET /admin: the settings, or the login page without a session.
     *
     * @throws HttpStatus
     */
    public function adminPage(Request $request): Response
    {
        // AdminToken forwards to admin_page_login when the cookie is missing on this page.
        if (! $this->config->bool('disable_admin_token') && ! $request->cookies->has(AdminToken::COOKIE_NAME)) {
            return $this->renderAdminLogin(null, null);
        }
        $this->token($request);

        return $this->renderAdminPage();
    }

    /**
     * POST /admin/invite: a user without a password, invited by mail when mail
     * is enabled and otherwise allowed to register.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function inviteUser(Request $request): Response
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);
        $email = Body::json($request)->string('email');

        if (User::findByMail($email) !== null) {
            throw ApiError::message('User already exists', 409);
        }

        $user = User::new($email);
        try {
            if ($this->config->mailEnabled()) {
                Mail::sendInvite($user, $this->inviteOrgId(), self::FAKE_ADMIN_UUID, $this->config->string('invitation_org_name'), null);
            } else {
                Invitation::new($user->email)->save();
            }
            $user->save();
        } catch (ApiError $error) {
            throw $error->withStatus(500);
        }

        return Json::response($user->toApi());
    }

    /**
     * POST /admin/test/smtp
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function testSmtp(Request $request): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);
        $email = Body::json($request)->string('email');

        if (! $this->config->mailEnabled()) {
            throw ApiError::message('Mail is not enabled');
        }
        Mail::sendTest($email);

        return new EmptyResponse;
    }

    /**
     * GET /admin/logout: the cookie goes, if the browser sent one.
     */
    public function logout(Request $request): Redirect
    {
        $response = new Redirect($this->adminPath());
        if ($request->cookies->has(AdminToken::COOKIE_NAME)) {
            $response->headers->setCookie(RocketCookie::removal(AdminToken::COOKIE_NAME, $this->adminPath()));
        }

        return $response;
    }

    /**
     * GET /admin/users
     *
     * @throws HttpStatus
     */
    public function getUsersJson(Request $request): Response
    {
        $this->token($request);

        $users = [];
        foreach (User::getAll() as [$user]) {
            $lastActive = $user->lastActive();
            $users[] = Json::sorted([
                ...$user->toApi(),
                'userEnabled' => $user->enabled,
                'createdAt' => self::localDateTime($user->created_at),
                'lastActive' => $lastActive === null ? null : self::localDateTime($lastActive),
            ]);
        }

        return Json::response($users);
    }

    /**
     * GET /admin/users/overview
     *
     * @throws HttpStatus
     */
    public function usersOverview(Request $request): Response
    {
        $this->token($request);

        $users = [];
        foreach (User::getAll() as [$user, $ssoIdentifier]) {
            $lastActive = $user->lastActive();
            $users[] = [
                ...$user->toApi(),
                'cipher_count' => Cipher::countOwnedByUser($user->uuid),
                'attachment_count' => Attachment::countByUser($user->uuid),
                'attachment_size' => Attachment::displaySize(Attachment::sizeByUser($user->uuid)),
                'user_enabled' => $user->enabled,
                'created_at' => self::localDateTime($user->created_at),
                'last_active' => $lastActive === null ? 'Never' : self::localDateTime($lastActive),
                'sso_identifier' => $ssoIdentifier ?? '',
            ];
        }

        return $this->renderPage('admin/users', $users);
    }

    /**
     * GET /admin/users/by-mail/{mail}
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function getUserByMailJson(Request $request, string $mail): Response
    {
        $this->token($request);
        $user = User::findByMail($mail) ?? throw ApiError::message("User doesn't exist", 404);

        return Json::response(self::userJson($user));
    }

    /**
     * GET /admin/users/{user_id}
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function getUserJson(Request $request, string $userId): Response
    {
        $this->token($request);

        return Json::response(self::userJson(self::userOr404(Uuid::parameter($request, $userId))));
    }

    /**
     * POST /admin/users/{user_id}/delete: the events of the memberships are
     * logged even when the user cannot be deleted.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function deleteUser(Request $request, string $userId): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $token = $this->token($request);
        $user = self::userOr404(Uuid::parameter($request, $userId));

        // The memberships and push devices before the user is gone.
        $memberships = Membership::findAnyStateByUser($user->uuid);
        $hasPushDevice = $this->config->bool('push_enabled') && Device::checkUserHasPushDevice($user->uuid);
        try {
            $user->deleteUser();
            $this->nt->sendLogout($user, null);
            if ($hasPushDevice) {
                Push::logoutToRelay($user, null);
            }
        } finally {
            foreach ($memberships as $member) {
                Event::log(Event::ORGANIZATION_USER_DELETED, $member->uuid, $member->org_uuid, self::ACTING_ADMIN_USER, self::DEVICE_TYPE, $token->ip);
            }
        }

        return new EmptyResponse;
    }

    /**
     * DELETE /admin/users/{user_id}/sso
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function deleteSsoUser(Request $request, string $userId): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $token = $this->token($request);
        $userId = Uuid::parameter($request, $userId);

        $memberships = Membership::findAnyStateByUser($userId);
        try {
            SsoUser::deleteByUser($userId);
        } finally {
            foreach ($memberships as $member) {
                Event::log(Event::ORGANIZATION_USER_UNLINKED_SSO, $member->uuid, $member->org_uuid, self::ACTING_ADMIN_USER, self::DEVICE_TYPE, $token->ip);
            }
        }

        return new EmptyResponse;
    }

    /**
     * POST /admin/users/{user_id}/deauth: every device and session goes.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function deauthUser(Request $request, string $userId): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);
        $user = self::userOr404(Uuid::parameter($request, $userId));

        $this->nt->sendLogout($user, null);

        if ($this->config->bool('push_enabled')) {
            foreach (Device::findPushDevicesByUser($user->uuid) as $device) {
                try {
                    Push::unregisterDevice($device->push_uuid);
                } catch (ApiError $error) {
                    logger()->error("Unable to unregister devices from Bitwarden server: {$error->displayText()}");
                }
            }
        }

        Device::deleteAllByUser($user->uuid);
        $user->resetSecurityStamp();
        $user->save();

        return new EmptyResponse;
    }

    /**
     * POST /admin/users/{user_id}/disable
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function disableUser(Request $request, string $userId): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);
        $user = self::userOr404(Uuid::parameter($request, $userId));

        $user->resetSecurityStamp();
        $user->enabled = false;
        try {
            $user->save();
        } finally {
            $this->nt->sendLogout($user, null);
            Device::deleteAllByUser($user->uuid);
        }

        return new EmptyResponse;
    }

    /**
     * POST /admin/users/{user_id}/enable
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function enableUser(Request $request, string $userId): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);
        $user = self::userOr404(Uuid::parameter($request, $userId));

        $user->enabled = true;
        $user->save();

        return new EmptyResponse;
    }

    /**
     * POST /admin/users/{user_id}/remove-2fa: every second factor goes, and
     * organizations that require one revoke the user.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function remove2fa(Request $request, string $userId): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $token = $this->token($request);
        $user = self::userOr404(Uuid::parameter($request, $userId));

        TwoFactor::deleteAllByUser($user->uuid);
        Device::clearTwofactorRememberByUser($user->uuid);
        OrgPolicy::enforceTwoFactorForUser($user, self::ACTING_ADMIN_USER, self::DEVICE_TYPE, $token->ip);
        $user->totp_recover = null;
        $user->save();

        return new EmptyResponse;
    }

    /**
     * POST /admin/users/{user_id}/invite/resend
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function resendUserInvite(Request $request, string $userId): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);
        $user = User::findByUuid(Uuid::parameter($request, $userId)) ?? throw ApiError::message("User doesn't exist", 404);

        if ($user->password_hash !== '') {
            throw ApiError::message('User already accepted invitation');
        }
        if ($this->config->mailEnabled()) {
            Mail::sendInvite($user, $this->inviteOrgId(), self::FAKE_ADMIN_UUID, $this->config->string('invitation_org_name'), null);
        }

        return new EmptyResponse;
    }

    /**
     * POST /admin/users/org_type: change the role of a member.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function updateMembershipType(Request $request): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $token = $this->token($request);
        $data = Body::json($request);
        // MembershipTypeData
        $userType = NumberOrString::optional($data, 'user_type') ?? throw new HttpStatus(422, 'Missing field `user_type`.');
        $userUuid = $data->string('user_uuid');
        $orgUuid = $data->string('org_uuid');

        $member = Membership::findByUserAndOrg($userUuid, $orgUuid) ?? throw ApiError::message("The specified user isn't member of the organization");
        $newType = Membership::typeFromString((string) $userType) ?? throw ApiError::message('Invalid type');

        // Removing an owner needs another confirmed one.
        if ($member->atype === Membership::TYPE_OWNER && $newType !== Membership::TYPE_OWNER
            && Membership::countConfirmedByOrgAndType($orgUuid, Membership::TYPE_OWNER) <= 1) {
            throw ApiError::message("Can't change the type of the last owner");
        }

        $member->atype = $newType;
        OrgPolicy::checkUserAllowed($member, 'modify');

        Event::log(Event::ORGANIZATION_USER_UPDATED, $member->uuid, $orgUuid, self::ACTING_ADMIN_USER, self::DEVICE_TYPE, $token->ip);
        $member->save();

        return new EmptyResponse;
    }

    /**
     * POST /admin/users/update_revision: every client syncs again.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function updateRevisionUsers(Request $request): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);
        User::updateAllRevisions();

        return new EmptyResponse;
    }

    /**
     * GET /admin/organizations/overview
     *
     * @throws HttpStatus
     */
    public function organizationsOverview(Request $request): Response
    {
        $this->token($request);

        $organizations = [];
        foreach (Organization::getAll() as $org) {
            $organizations[] = [
                ...$org->toApi(),
                'user_count' => Membership::countByOrg($org->uuid),
                'cipher_count' => Cipher::countByOrg($org->uuid),
                'collection_count' => OrgCollection::countByOrg($org->uuid),
                'group_count' => Group::countByOrg($org->uuid),
                'event_count' => Event::countByOrg($org->uuid),
                'attachment_count' => Attachment::countByOrg($org->uuid),
                'attachment_size' => Attachment::displaySize(Attachment::sizeByOrg($org->uuid)),
            ];
        }

        return $this->renderPage('admin/organizations', $organizations);
    }

    /**
     * POST /admin/organizations/{org_id}/delete
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function deleteOrganization(Request $request, string $orgId): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);
        $org = Organization::findByUuid(Uuid::parameter($request, $orgId)) ?? throw ApiError::message("Organization doesn't exist");
        $org->deleteOrganization();

        return new EmptyResponse;
    }

    /**
     * GET /admin/diagnostics
     *
     * @throws HttpStatus
     */
    public function diagnostics(Request $request): Response
    {
        $this->token($request);
        $ipHeader = $this->ipHeader($request) ?? '';

        $runningWithinContainer = self::isRunningInContainer();
        $hasHttpAccess = $this->hasHttpAccess();
        $usesProxy = array_any(['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy'], static fn (string $name): bool => getenv($name) !== false);
        $resolved = gethostbynamel('github.com');

        [$latestRelease, $latestCommit, $latestWebRelease] = $this->releaseInfo($hasHttpAccess);
        $activeWebRelease = WebVault::activeRelease($this->config);

        // Vaultwarphpen with the Vaultwarden release it mirrors. The newest version
        // is compared like the installed one, a release with releases and a
        // commit with commits; the page shows "Ok" when both read the same.
        $installed = Release::installed();
        $currentRelease = Release::NAME." {$installed} (Vaultwarden ".Release::vaultwarden().')';
        $latest = Release::isTagged() ? $latestRelease : $latestCommit;

        $diagnostics = [
            'dns_resolved' => $resolved === false || $resolved === [] ? 'Unable to resolve domain name.' : $resolved[0],
            'current_release' => $currentRelease,
            'latest_release' => match (true) {
                $latest === '-' => '-',
                $latest === $installed => $currentRelease,
                default => Release::NAME." {$latest}",
            },
            'latest_commit' => $latestCommit,
            'web_vault_enabled' => $this->config->bool('web_vault_enabled'),
            'active_web_release' => $activeWebRelease,
            'latest_web_release' => $latestWebRelease,
            'web_vault_compare' => self::webVaultCompare($activeWebRelease, $latestWebRelease),
            'running_within_container' => $runningWithinContainer,
            'container_base_image' => $runningWithinContainer ? self::containerBaseImage() : 'Not applicable',
            'has_http_access' => $hasHttpAccess,
            'ip_header_exists' => $ipHeader !== '',
            'ip_header_match' => $ipHeader === $this->config->string('ip_header'),
            'ip_header_name' => $ipHeader,
            'ip_header_config' => $this->config->string('ip_header'),
            'uses_proxy' => $usesProxy,
            'enable_websocket' => $this->config->bool('enable_websocket'),
            'db_type' => match (DatabaseUrl::type($this->config->string('database_url'), $this->config)) {
                'mysql' => 'MySQL',
                'postgresql' => 'PostgreSQL',
                'sqlite' => 'SQLite',
            },
            'db_version' => $this->databaseVersion(),
            'admin_url' => $this->config->string('domain_origin').$this->adminPath().'/diagnostics',
            'overrides' => implode(', ', $this->config->overrides),
            'config_file_status' => $this->config->fileStatus->value,
            'template_overrides' => implode(', ', $this->templateOverrides()),
            'invalid_env_vars' => implode(', ', $this->config->env->invalid),
            'invalid_feature_flags' => array_keys(FeatureFlags::parse($this->config->string('experimental_client_feature_flags'), 'invalid')),
            // PHP's runtime takes the place of Rust's.
            'host_arch' => php_uname('m').' (PHP '.PHP_VERSION.', '.PHP_SAPI.')',
            'host_os' => PHP_OS_FAMILY === 'Darwin' ? 'macos' : strtolower(PHP_OS_FAMILY),
            'tz_env' => (string) getenv('TZ'),
            'server_time_local' => self::localZoneNow()->format('Y-m-d H:i:s P'),
            // The clocks are read as late as possible, to keep the differences small.
            'server_time' => Dates::now()->format('Y-m-d H:i:s \U\T\C'),
            'ntp_time' => $this->ntpTime($hasHttpAccess),
        ];

        return $this->renderPage('admin/diagnostics', Json::sorted($diagnostics));
    }

    /**
     * GET /admin/diagnostics/config: the settings for a support request, masked.
     *
     * @throws HttpStatus
     */
    public function getDiagnosticsConfig(Request $request): Response
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);

        return Json::response($this->config->supportJson());
    }

    /**
     * GET /admin/diagnostics/http?code=: an error with that status, to check
     * that a reverse proxy leaves error responses alone.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function getDiagnosticsHttp(Request $request): never
    {
        $this->token($request);
        $code = Query::first($request, 'code');
        if ($code === null || ! preg_match('/^\+?[0-9]+$/D', $code) || (int) ltrim($code, '+') > 65_535 || strlen(ltrim($code, '+0')) > 5) {
            $this->forward($request);
        }
        $code = (int) ltrim($code, '+');

        // Status::from_code: a status Rocket does not know is answered with 400.
        throw ApiError::message("Testing error {$code} response", in_array($code, self::ROCKET_STATUSES, true) ? $code : 400);
    }

    /**
     * POST /admin/config: save the settings to config.json.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function postConfig(Request $request): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);

        $data = json_decode(Body::content($request, Body::JSON_LIMIT), false, 512, JSON_BIGINT_AS_STRING);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new HttpStatus(400, 'Invalid JSON: '.json_last_error_msg());
        }
        if (! $data instanceof stdClass) {
            throw new HttpStatus(422, 'Expected a JSON object.');
        }
        try {
            $builder = ConfigBuilder::fromJson($data);
        } catch (ConfigException $exception) {
            throw new HttpStatus(422, $exception->getMessage());
        }

        try {
            $this->config->updateConfig($builder);
        } catch (ConfigException $exception) {
            throw ApiError::message("Unable to save config: {$exception->getMessage()}");
        }

        return new EmptyResponse;
    }

    /**
     * POST /admin/config/delete: back to the environment and the defaults.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function deleteConfig(Request $request): EmptyResponse
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);

        try {
            $this->config->deleteUserConfig();
        } catch (ConfigException $exception) {
            throw ApiError::message("Unable to delete config: {$exception->getMessage()}");
        }

        return new EmptyResponse;
    }

    /**
     * POST /admin/config/backup_db: a copy of the SQLite database next to it.
     *
     * @throws ApiError
     * @throws HttpStatus
     */
    public function backupDb(Request $request): Response
    {
        $this->requireFormat($request, 'application/json');
        $this->token($request);

        if (! $this->canBackup()) {
            throw ApiError::message("Can't back up current DB (Only SQLite supports this feature)");
        }

        // backup_sqlite: named like the database URL names the database.
        $url = $this->config->string('database_url');
        $database = str_starts_with($url, 'sqlite://') ? substr($url, strlen('sqlite://')) : $url;
        $folder = str_contains($database, '/') ? substr($database, 0, (int) strrpos($database, '/') + 1) : '';
        $backup = $folder.'db_'.Dates::now()->format('Ymd_His').'.sqlite3';

        try {
            $this->databases->connection()->statement('VACUUM INTO ?', [$this->config->absolutePath($backup)]);
        } catch (QueryException) {
            throw ApiError::message('Backup was unsuccessful '.ApiError::message('VACUUM INTO failed')->displayText());
        }

        return new Response("Backup to '{$backup}' was successful", 200, ['Content-Type' => 'text/plain; charset=utf-8']);
    }

    /**
     * The AdminToken guard.
     *
     * @throws HttpStatus
     */
    private function token(Request $request): AdminToken
    {
        return AdminToken::fromRequest($request, $this->config, $this->jwt);
    }

    /**
     * A route with `format = ...` matches no other request.
     *
     * @throws HttpStatus
     */
    private function requireFormat(Request $request, string $format): void
    {
        if (! Accept::matchesFormat($request, $format)) {
            throw new HttpStatus(404, "Not a request for {$format}.");
        }
    }

    /**
     * A parameter that does not parse forwards the request: GET requests end
     * at the web vault's catch-all, which finds no such file.
     *
     * @throws HttpStatus
     */
    private function forward(Request $request): never
    {
        $get = in_array($request->getMethod(), ['GET', 'HEAD'], true) && $this->config->bool('web_vault_enabled');

        throw new HttpStatus($get ? 404 : 422, 'A parameter does not parse.');
    }

    private function adminPath(): string
    {
        return $this->config->string('domain_path').self::ADMIN_PATH;
    }

    /**
     * The path below /admin, as the PathBuf of its segments; empty when it has
     * a segment a path may not have.
     */
    private function requestedPage(Request $request): string
    {
        $path = substr($request->getPathInfo(), strlen($this->adminPath()));
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            $segment = rawurldecode($segment);
            if ($segment === '') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
            } elseif (str_starts_with($segment, '.') || str_starts_with($segment, '*') || str_contains($segment, '/')
                || preg_match('/[:><]$/', $segment) === 1) {
                return '';
            } else {
                $segments[] = $segment;
            }
        }

        return implode('/', $segments);
    }

    /**
     * The Secure guard: whether the request came in over HTTPS.
     */
    private function isSecure(Request $request): bool
    {
        return Secure::https($request);
    }

    /**
     * validate_token: an Argon2 PHC string is verified, a plain token compared.
     */
    private function validateToken(string $token): bool
    {
        $adminToken = $this->config->optionalString('admin_token');
        if ($adminToken === null) {
            return false;
        }
        if (! str_starts_with($adminToken, '$argon2')) {
            return hash_equals(trim($adminToken), trim($token));
        }

        // One verification, as in Rust: libsodium only where PHP was built without Argon2.
        try {
            return defined('PASSWORD_ARGON2ID')
                ? password_verify(trim($token), $adminToken)
                : function_exists('sodium_crypto_pwhash_str_verify') && sodium_crypto_pwhash_str_verify($adminToken, trim($token));
        } catch (Throwable $exception) {
            logger()->error("The configured Argon2 PHC in `ADMIN_TOKEN` is invalid: {$exception->getMessage()}");

            return false;
        }
    }

    /**
     * The organization of admin invitations: none, or SSO's.
     */
    private function inviteOrgId(): string
    {
        return $this->config->bool('sso_enabled') ? self::FAKE_SSO_IDENTIFIER : self::FAKE_ADMIN_UUID;
    }

    /**
     * @throws ApiError
     */
    private static function userOr404(string $userId): User
    {
        return User::findByUuid($userId) ?? throw ApiError::message("User doesn't exist", 404);
    }

    /**
     * @return array<string, mixed>
     */
    private static function userJson(User $user): array
    {
        return Json::sorted([
            ...$user->toApi(),
            'userEnabled' => $user->enabled,
            'createdAt' => self::localDateTime($user->created_at),
        ]);
    }

    /**
     * util::format_naive_datetime_local with "%Y-%m-%d %H:%M:%S %Z": in the
     * TZ time zone with its abbreviation, else in the local one with its offset.
     */
    private static function localDateTime(DateTimeImmutable $date): string
    {
        $zone = getenv('TZ');
        try {
            $timezone = is_string($zone) && $zone !== '' ? new DateTimeZone($zone) : null;
        } catch (Throwable) {
            $timezone = null;
        }

        return $date->setTimezone($timezone ?? LocalTimeZone::get())->format($timezone === null ? 'Y-m-d H:i:s P' : 'Y-m-d H:i:s T');
    }

    /**
     * chrono's Local::now().
     */
    private static function localZoneNow(): DateTimeImmutable
    {
        return Dates::now()->setTimezone(LocalTimeZone::get());
    }

    private function renderAdminLogin(?string $message, ?string $redirect, int $status = 200): Response
    {
        $html = $this->templates->render(self::BASE_TEMPLATE, [
            'page_content' => 'admin/login',
            'error' => $message === null ? null : "Error: {$message}",
            'redirect' => $redirect,
            'urlpath' => $this->config->string('domain_path'),
        ]);

        return self::html($html, $status);
    }

    private function renderAdminPage(): Response
    {
        return $this->renderPage('admin/settings', [
            'config' => $this->config->prepareJson(),
            'can_backup' => $this->canBackup(),
        ]);
    }

    /**
     * AdminTemplateData
     */
    private function renderPage(string $page, mixed $data): Response
    {
        return self::html($this->templates->render(self::BASE_TEMPLATE, [
            'page_content' => $page,
            'page_data' => $data,
            'logged_in' => true,
            'urlpath' => $this->config->string('domain_path'),
            'sso_enabled' => $this->config->bool('sso_enabled'),
        ]));
    }

    private static function html(string $html, int $status = 200): Response
    {
        return new Response($html, $status, ['Content-Type' => 'text/html; charset=utf-8']);
    }

    /**
     * CAN_BACKUP: only SQLite databases can be backed up.
     */
    private function canBackup(): bool
    {
        return DatabaseUrl::type($this->config->string('database_url'), $this->config) === 'sqlite';
    }

    /**
     * The IpHeader guard: the configured client IP header, or the first of
     * the usual ones the request has.
     */
    private function ipHeader(Request $request): ?string
    {
        foreach ([$this->config->string('ip_header'), 'X-Client-IP', 'X-Real-IP', 'X-Forwarded-For'] as $header) {
            if ($request->headers->has($header)) {
                return $header;
            }
        }

        return null;
    }

    /**
     * Whether github.com answers, through the client that checks for updates.
     */
    private function hasHttpAccess(): bool
    {
        try {
            [$status] = HttpClient::send('HEAD', 'https://github.com/'.Release::REPOSITORY);

            return $status >= 200 && $status < 300;
        } catch (ApiError) {
            return false;
        }
    }

    /**
     * get_release_info: the latest release and commit of Vaultwarphpen and the
     * latest web vault, "-" for what cannot be fetched.
     *
     * @return array{string, string, string}
     */
    private function releaseInfo(bool $hasHttpAccess): array
    {
        if (! $hasHttpAccess) {
            return ['-', '-', '-'];
        }

        /** @var array{string, string, string} */
        return $this->cache->remember('vaultwarden:admin:release-info', self::RELEASE_INFO_TTL, function (): array {
            $release = $this->githubJson('https://api.github.com/repos/'.Release::REPOSITORY.'/releases/latest', 'tag_name');
            $commit = $this->githubJson('https://api.github.com/repos/'.Release::REPOSITORY.'/commits/main', 'sha');
            $webRelease = $this->githubJson('https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest', 'tag_name');

            return [
                $release === null ? '-' : ltrim($release, 'v'),
                $commit === null ? '-' : substr($commit, 0, 8),
                $webRelease === null ? '-' : ltrim($webRelease, 'v'),
            ];
        });
    }

    /**
     * A string field of a successful GitHub API response.
     */
    private function githubJson(string $url, string $field): ?string
    {
        try {
            [$status, $body] = HttpClient::send('GET', $url);
        } catch (ApiError) {
            return null;
        }
        $json = json_decode($body);

        return $status >= 200 && $status < 300 && $json instanceof stdClass && is_string($json->{$field} ?? null) ? $json->{$field} : null;
    }

    /**
     * get_ntp_time: the time of Cloudflare's trace.
     */
    private function ntpTime(bool $hasHttpAccess): string
    {
        if ($hasHttpAccess) {
            try {
                [$status, $trace] = HttpClient::send('GET', 'https://cloudflare.com/cdn-cgi/trace');
                if ($status >= 200 && $status < 300) {
                    foreach (explode("\n", $trace) as $line) {
                        [$key, $value] = array_pad(explode('=', $line, 2), 2, null);
                        if ($key === 'ts' && $value !== null) {
                            $seconds = explode('.', $value)[0];
                            if (preg_match('/^-?[0-9]+$/D', $seconds) === 1) {
                                return gmdate('Y-m-d H:i:s \U\T\C', (int) $seconds);
                            }

                            break;
                        }
                    }
                }
            } catch (ApiError) {
                // Below.
            }
        }

        return 'Unable to fetch NTP time.';
    }

    /**
     * web_vault_compare: -1, 0 or 1, with 2025.1.1 for a version that does not parse.
     */
    public static function webVaultCompare(string $active, string $latest): int
    {
        $fallback = SemVer::parse('2025.1.1') ?? [[2025, 1, 1], [], []];

        return SemVer::compare(SemVer::parse($active) ?? $fallback, SemVer::parse($latest) ?? $fallback);
    }

    /**
     * is_running_in_container
     */
    private static function isRunningInContainer(): bool
    {
        return array_any(['/.dockerenv', '/run/.containerenv', '/run/secrets/kubernetes.io', '/var/run/secrets/kubernetes.io'], static fn (string $path): bool => file_exists($path));
    }

    /**
     * container_base_image
     */
    private static function containerBaseImage(): string
    {
        return match (true) {
            file_exists('/etc/debian_version') => 'Debian',
            file_exists('/etc/alpine-release') => 'Alpine',
            default => 'Unknown',
        };
    }

    /**
     * get_sql_server_version
     */
    private function databaseVersion(): string
    {
        $sqlite = DatabaseUrl::type($this->config->string('database_url'), $this->config) === 'sqlite';
        try {
            $version = $this->databases->connection()->scalar($sqlite ? 'SELECT sqlite_version()' : 'SELECT version()');
        } catch (QueryException) {
            return 'Unknown';
        }

        return is_string($version) ? $version : 'Unknown';
    }

    /**
     * check_template_overrides: the folders of the templates folder that hold templates.
     *
     * @return list<string>
     */
    private function templateOverrides(): array
    {
        $folder = $this->config->path('templates_folder');
        $overrides = [];
        foreach (['admin', 'email', 'scss'] as $name) {
            if (self::folderHasTemplates("{$folder}/{$name}")) {
                $overrides[] = $name;
            }
        }
        if (self::folderHasTemplates($folder)) {
            $overrides[] = 'other';
        }

        return $overrides;
    }

    /**
     * Files ending in .hbs whose names start with a letter or digit.
     */
    private static function folderHasTemplates(string $folder): bool
    {
        foreach (is_dir($folder) ? (scandir($folder) ?: []) : [] as $file) {
            if (is_file("{$folder}/{$file}") && preg_match('/^[A-Za-z0-9].*\.hbs$/Di', $file) === 1) {
                return true;
            }
        }

        return false;
    }
}
