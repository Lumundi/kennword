<?php

namespace App\Http\Controllers;

use App\Auth\AuthMethod;
use App\Auth\AuthTokens;
use App\Auth\ClientIp;
use App\Auth\DuoOidc;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\LoginClaims;
use App\Auth\MasterPasswordPolicy;
use App\Auth\Secure;
use App\Auth\Sso\Sso;
use App\Config\Config;
use App\Http\Accept;
use App\Http\ApiError;
use App\Http\Controllers\TwoFactor\AuthenticatorController;
use App\Http\Controllers\TwoFactor\EmailController;
use App\Http\Controllers\TwoFactor\TwoFactorController;
use App\Http\Controllers\TwoFactor\WebauthnController;
use App\Http\Controllers\TwoFactor\YubikeyController;
use App\Http\Data\Body;
use App\Http\Data\Query;
use App\Http\Data\RegisterData;
use App\Http\EmptyResponse;
use App\Http\HttpStatus;
use App\Http\Json;
use App\Http\Redirect;
use App\Http\RocketCookie;
use App\Mail\Mail;
use App\Models\AuthRequest;
use App\Models\Device;
use App\Models\Event;
use App\Models\Invitation;
use App\Models\OrganizationApiKey;
use App\Models\OrgPolicy;
use App\Models\Send;
use App\Models\SsoAuth;
use App\Models\SsoUser;
use App\Models\TwoFactor;
use App\Models\TwoFactorIncomplete;
use App\Models\User;
use App\Support\CheckedInt;
use App\Support\Dates;
use App\Support\EscapeDebug;
use App\Support\FormUrlencoded;
use App\Support\Push;
use App\Support\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use stdClass;

/**
 * src/api/identity.rs
 */
final readonly class IdentityController
{
    /**
     * SSO_BINDING_COOKIE: binds an SSO login to the browser that started it.
     */
    private const string SSO_BINDING_COOKIE = 'VW_SSO_BINDING';

    public function __construct(
        private Config $config,
        private Jwt $jwt,
        private RateLimiter $limiter,
        private AccountsController $accounts,
    ) {}

    /**
     * POST /identity/connect/token: password, refresh token and API key logins.
     */
    public function login(Request $request): Response
    {
        $data = Body::form($request);
        // ConnectData: names without case, each with an alias without underscores.
        $field = static fn (string $name): ?string => Body::optionalFormField($data, array_values(array_unique([$name, str_replace('_', '', $name)])));
        // The only field that is not an Option: missing or repeated, the form is rejected.
        $grantType = $field('grant_type') ?? throw new HttpStatus(422, 'Field `grant_type` is missing or repeated.');

        $ip = ClientIp::resolve($request, $this->config);
        // ClientHeaders: an unknown browser without a valid Device-Type.
        $deviceType = CheckedInt::parseI32((string) $request->headers->get('Device-Type')) ?? 14;
        $required = static function (string $name, string $message) use ($field): string {
            return $field($name) ?? throw ApiError::message($message);
        };
        // Set once the user is known, for the event log.
        $userId = null;

        try {
            $response = $this->dispatchLogin($grantType, $data, $field, $required, $ip, $userId);
        } catch (ApiError $error) {
            if ($userId !== null && $error->event !== null) {
                Event::logUser($error->event, $userId, $deviceType, $ip);
            }

            throw $error;
        }
        if ($userId !== null) {
            Event::logUser(Event::USER_LOGGED_IN, $userId, $deviceType, $ip);
        }

        return $response;
    }

    /**
     * @param  array<string, list<string>>  $data
     * @param  callable(string): ?string  $field
     * @param  callable(string, string): string  $required
     */
    private function dispatchLogin(string $grantType, array $data, callable $field, callable $required, string $ip, ?string &$userId): Response
    {
        return match (true) {
            $grantType === 'refresh_token' => $this->refreshLogin($required('refresh_token', 'refresh_token cannot be blank'), $field('client_id'), $ip),
            $grantType === 'password' && $this->config->bool('sso_enabled') && $this->config->bool('sso_only') => throw ApiError::message('SSO sign-in is required'),
            $grantType === 'password' => $this->passwordLogin(
                clientId: $required('client_id', 'client_id cannot be blank'),
                password: $required('password', 'password cannot be blank'),
                scope: $required('scope', 'scope cannot be blank'),
                username: $required('username', 'username cannot be blank'),
                device: [
                    $required('device_identifier', 'device_identifier cannot be blank'),
                    $required('device_name', 'device_name cannot be blank'),
                    $required('device_type', 'device_type cannot be blank'),
                ],
                authRequest: $field('authrequest'),
                twoFactor: [
                    'provider' => CheckedInt::parseI32((string) $field('two_factor_provider')),
                    'token' => $field('two_factor_token'),
                    'remember' => CheckedInt::parseI32((string) $field('two_factor_remember')),
                ],
                ip: $ip,
                userId: $userId,
            ),
            $grantType === 'client_credentials' => $this->apiKeyLogin(
                clientId: $required('client_id', 'client_id cannot be blank'),
                clientSecret: $required('client_secret', 'client_secret cannot be blank'),
                scope: $required('scope', 'scope cannot be blank'),
                field: $field,
                ip: $ip,
                userId: $userId,
            ),
            $grantType === 'authorization_code' && $this->config->bool('sso_enabled') => $this->ssoLogin(
                clientId: $required('client_id', 'client_id cannot be blank'),
                code: $required('code', 'code cannot be blank'),
                codeVerifier: $required('code_verifier', 'code verifier cannot be blank'),
                device: [
                    $required('device_identifier', 'device_identifier cannot be blank'),
                    $required('device_name', 'device_name cannot be blank'),
                    $required('device_type', 'device_type cannot be blank'),
                ],
                scope: $field('scope'),
                twoFactor: [
                    'provider' => CheckedInt::parseI32((string) $field('two_factor_provider')),
                    'token' => $field('two_factor_token'),
                    'remember' => CheckedInt::parseI32((string) $field('two_factor_remember')),
                ],
                ip: $ip,
                userId: $userId,
            ),
            $grantType === 'authorization_code' => throw ApiError::message('SSO sign-in is not available'),
            $grantType === 'send_access' => $this->sendAccessLogin(
                fn (): string => $required('client_id', 'client_id cannot be blank'),
                // Fields without aliases.
                Body::optionalFormField($data, ['send_id']),
                Body::optionalFormField($data, ['password_hash_b64']),
                $ip,
            ),
            default => throw ApiError::message('Invalid type', logMessage: EscapeDebug::of($grantType)),
        };
    }

    /**
     * The send_access grant (auth::send::SendTokens): a two-minute token for
     * the Send behind an access id, checked against its password.
     *
     * @param  callable(): string  $clientId  Required, but checked after the rate limit
     *
     * @throws ApiError
     */
    private function sendAccessLogin(callable $clientId, ?string $accessId, ?string $password, string $ip): Response
    {
        $this->limiter->check('unauthenticated', $ip);
        $clientId();
        $accessId ?? throw ApiError::message('send_id cannot be blank');

        $invalid = static fn (string $log, string $type): ApiError => ApiError::json(
            Json::sorted(['kind' => 'expected_server', 'error' => 'invalid_grant', 'send_access_error_type' => $type]),
            $log,
            404,
        );

        $sendId = Send::uuidFromAccessId($accessId) ?? throw $invalid("Can't convert ".EscapeDebug::of($accessId), 'send_id_invalid');
        $send = Send::findByUuid($sendId) ?? throw $invalid("Can't find {$sendId}", 'send_id_invalid');

        if ($send->max_access_count !== null && $send->access_count >= $send->max_access_count) {
            throw $invalid("Send {$sendId}, max access reached", 'send_id_invalid');
        }
        if (! $send->isAccessible()) {
            throw $invalid("Send {$sendId}, not accessible", 'send_id_invalid');
        }

        if ($send->password_hash !== null) {
            if ($password === null) {
                throw ApiError::json(
                    Json::sorted(['kind' => 'expected_server', 'error' => 'invalid_request', 'send_access_error_type' => 'password_hash_b64_required']),
                    'Password required',
                );
            }
            if (! $send->checkPassword($password)) {
                throw $invalid("Send {$sendId}, Invalid password from {$ip}", 'password_hash_b64_invalid');
            }
        }

        $now = Dates::now()->getTimestamp();
        $claims = ['nbf' => $now, 'exp' => $now + 120, 'iss' => $this->jwt->issuer(JwtIssuer::Send), 'sub' => $sendId];

        return Json::response(Json::sorted([
            'access_token' => $this->jwt->encode($claims),
            'expires_in' => $claims['exp'] - Dates::now()->getTimestamp(),
            'token_type' => 'Bearer',
            'scope' => 'api.send.access',
        ]));
    }

    /**
     * GET /identity/sso/prevalidate: a short token the clients pass on to
     * /identity/connect/authorize (sso::encode_ssotoken_claims).
     *
     * @throws ApiError
     */
    public function prevalidate(): Response
    {
        if (! $this->config->bool('sso_enabled')) {
            throw ApiError::message('SSO sign-in is not available');
        }
        $now = Dates::now()->getTimestamp();

        return Json::response(['token' => $this->jwt->encode([
            'nbf' => $now,
            'exp' => $now + 120,
            'iss' => $this->jwt->issuer(JwtIssuer::Sso),
            'sub' => 'vaultwarden',
        ])]);
    }

    /**
     * POST /identity/accounts/prelogin
     */
    public function postPrelogin(Request $request): Response
    {
        return $this->prelogin($request);
    }

    /**
     * POST /identity/accounts/prelogin/password
     */
    public function preloginPassword(Request $request): Response
    {
        return $this->prelogin($request);
    }

    /**
     * POST /identity/accounts/register/send-verification-email: without mail
     * verification the token comes back directly, as JSON only when the
     * client asks for it.
     */
    public function registerVerificationEmail(Request $request): Response
    {
        $body = Body::json($request);
        $email = $body->string('email');
        $name = $body->optionalString('name');

        $this->limiter->check('unauthenticated', ClientIp::resolve($request, $this->config));

        // Signup must be allowed, or an invitation exist.
        if (! ($this->config->isSignupAllowed($email)
            || (! $this->config->mailEnabled() && Invitation::findByMail($email) !== null))) {
            throw ApiError::message('Registration not allowed or user already exists');
        }

        $sendMail = $this->config->mailEnabled() && $this->config->bool('signups_verify');
        $now = Dates::now()->getTimestamp();
        // RegisterVerifyClaims, valid for 30 minutes.
        $token = $this->jwt->encode([
            'nbf' => $now,
            'exp' => $now + 1_800,
            'iss' => $this->jwt->issuer(JwtIssuer::RegisterVerify),
            'sub' => $email,
            'name' => $name,
            'verified' => $sendMail,
        ]);

        if ($sendMail) {
            $user = User::findByMail($email);
            if ($user !== null && $user->private_key !== null) {
                // Hide that the account exists: the mail path takes about as long.
                usleep(random_int(900, 1_100) * 1_000);
            } else {
                Mail::sendRegisterVerifyEmail($email, $token);
            }

            return (new EmptyResponse)->setStatusCode(204);
        }

        return Accept::prefersJson($request)
            ? Json::response($token)
            : new Response($token, 200, ['Content-Type' => 'text/plain; charset=utf-8']);
    }

    /**
     * POST /identity/accounts/register/verification-email-clicked: whether the
     * link of the mail still leads to a registration.
     */
    public function registerVerificationEmailClicked(Request $request): EmptyResponse
    {
        $body = Body::json($request);
        $email = $body->string('email');
        $token = $body->string('emailVerificationToken');

        try {
            $claims = $this->jwt->decode($token, JwtIssuer::RegisterVerify, fields: Jwt::REGISTER_VERIFY_CLAIMS);
            $tokenValid = $claims['verified'] === true && is_string($claims['sub']) && strcasecmp($claims['sub'], $email) === 0;
        } catch (ApiError) {
            $tokenValid = false;
        }
        $user = User::findByMail($email);
        $userExists = $user !== null && ($user->password_hash !== '' || $user->private_key !== null);

        if (! $tokenValid || $userExists) {
            throw ApiError::message('Expired link. Please restart registration or try logging in. You may already have an account');
        }

        return new EmptyResponse;
    }

    /**
     * POST /identity/accounts/register/finish
     */
    public function registerFinish(Request $request): Response
    {
        $data = RegisterData::fromFields(Body::json($request));
        $this->limiter->check('unauthenticated', ClientIp::resolve($request, $this->config));

        return $this->accounts->register($data);
    }

    /**
     * Invalid or missing refresh tokens answer {"error":"invalid_grant"}, which the clients look for.
     */
    private function refreshLogin(string $refreshToken, ?string $clientId, string $ip): Response
    {
        try {
            [$device, $tokens] = AuthTokens::refresh($refreshToken, $clientId, $ip, $this->jwt, $this->config);
        } catch (ApiError $error) {
            throw ApiError::json(['error' => 'invalid_grant'], "Unable to refresh login credentials: {$error->getMessage()}");
        }

        // Saved to track usage and the new status.
        $device->save();

        return Json::response(Json::sorted([
            'refresh_token' => $tokens->refreshToken(),
            'access_token' => $tokens->accessToken(),
            'expires_in' => $tokens->expiresIn(),
            'token_type' => 'Bearer',
            'scope' => $tokens->scope(),
        ]));
    }

    /**
     * @param  array{string, string, string}  $device  Identifier, name and type
     * @param  array{provider: ?int, token: ?string, remember: ?int}  $twoFactor  The second factor the client sends
     * @param  ?string  $userId  Set once the user is known
     *
     * @param-out string $userId
     */
    private function passwordLogin(string $clientId, string $password, string $scope, string $username, array $device, ?string $authRequest, array $twoFactor, string $ip, ?string &$userId): Response
    {
        AuthMethod::Password->checkScope($scope);
        $this->limiter->check('login', $ip);

        $username = trim($username);
        $logUsername = EscapeDebug::of($username);
        $user = User::findByMail($username)
            ?? throw ApiError::message('Username or password is incorrect. Try again', logMessage: "IP: {$ip}. Username: {$logUsername}.");
        $userId = $user->uuid;

        $failed = "IP: {$ip}. Username: {$logUsername}.";
        if ($authRequest !== null) {
            // A login with a device: the access code of an approved request stands in for the password.
            $request = AuthRequest::findByUuidAndUser($authRequest, $user->uuid)
                ?? throw ApiError::message('Auth request not found. Try again.', logMessage: $failed, event: Event::USER_FAILED_LOG_IN);
            $expired = Dates::now() >= $request->creation_date->modify('+5 minutes');
            if ($request->user_uuid !== $user->uuid || $request->approved !== true || $request->authentication_date !== null || $expired
                || $ip !== $request->request_ip || ! $request->checkAccessCode($password)) {
                throw ApiError::message('Username or access code is incorrect. Try again', logMessage: $failed, event: Event::USER_FAILED_LOG_IN);
            }
        } elseif (! $user->checkValidPassword($password)) {
            throw ApiError::message('Username or password is incorrect. Try again', logMessage: $failed, event: Event::USER_FAILED_LOG_IN);
        }
        if (! $user->enabled) {
            throw ApiError::message('This user has been disabled', logMessage: "IP: {$ip}. Username: {$logUsername}.", event: Event::USER_FAILED_LOG_IN);
        }

        if ($authRequest === null) {
            $this->accounts->kdfUpgrade($user, $password);
        }

        if ($user->verified_at === null && $this->config->mailEnabled() && $this->config->bool('signups_verify')) {
            $this->remindToVerify($user);

            // The login fails until the address is verified.
            throw ApiError::message('Please verify your email before trying again.', logMessage: "IP: {$ip}. Username: {$logUsername}.", event: Event::USER_FAILED_LOG_IN);
        }

        $loginDevice = $this->getDevice($user, ...$device);
        $twofactorToken = $this->twofactorAuth($user, $loginDevice, $twoFactor, $clientId, $ip);

        // A request works for one login; marked after 2FA, so that the prompt does not use it up.
        if ($authRequest !== null && ! AuthRequest::setAuthenticationDate($authRequest)) {
            throw ApiError::message('Username or access code is incorrect. Try again', logMessage: $failed, event: Event::USER_FAILED_LOG_IN);
        }

        return $this->authenticatedResponse($user, $loginDevice, AuthTokens::new($loginDevice, $user, AuthMethod::Password, $clientId, $this->jwt), $ip, $twofactorToken);
    }

    /**
     * identity::sso_login: the code from the provider logs in the user it
     * names, linked by its identity or matched by email, or signs one up.
     * The two-factor login comes before the code is used up.
     *
     * @param  array{string, string, string}  $device  Identifier, name and type
     * @param  array{provider: ?int, token: ?string, remember: ?int}  $twoFactor
     * @param  ?string  $userId  Set once the user is logged in
     *
     * @param-out string $userId
     *
     * @throws ApiError
     */
    private function ssoLogin(string $clientId, string $code, string $codeVerifier, array $device, ?string $scope, array $twoFactor, string $ip, ?string &$userId): Response
    {
        AuthMethod::Sso->checkScope($scope);
        $this->limiter->check('login', $ip);

        $sso = new Sso($this->config, $this->jwt);
        [$auth, $infos] = $sso->exchangeCode($code, $codeVerifier);
        // err_silent!: the reason is logged above.
        $failed = static fn (string $message): ApiError => ApiError::silent($message, event: Event::USER_FAILED_LOG_IN);

        $userWithSso = SsoUser::findByIdentifier($infos->identifier);
        if ($userWithSso === null) {
            $byMail = SsoUser::findByMail($infos->email);
            if ($byMail !== null) {
                [$user, $linked] = $byMail;
                if ($linked !== null) {
                    logger()->error("Login failure ({$infos->identifier}), existing SSO user ({$user->uuid}) with same email ({$user->email})");
                    throw $failed('Existing SSO user with same email');
                }
                if ($user->private_key === null && ! $this->config->bool('sso_signups_allowed') && ! $this->config->isEmailDomainAllowed($user->email)
                    && ! $this->config->mailEnabled() && Invitation::findByMail($user->email) === null) {
                    logger()->error("Login failure ({$infos->identifier}), no invitation with email ({$user->email}) was found");
                    throw $failed('Missing invitation');
                }
                if ($user->private_key !== null && ! $this->config->bool('sso_signups_match_email')) {
                    logger()->error("Login failure ({$infos->identifier}), existing non SSO user ({$user->uuid}) with same email ({$user->email}) and association is disabled");
                    throw $failed('Existing non SSO user with same email');
                }
                if ($infos->emailVerified === null && ! $this->config->bool('sso_allow_unknown_email_verification')) {
                    logger()->error("Login failure ({$infos->identifier}), existing non SSO user ({$user->uuid}) with same email ({$user->email}) and email verification status is unknown");
                    throw $failed('Email verification status is unknown');
                }
                if ($infos->emailVerified === false) {
                    logger()->error("Login failure ({$infos->identifier}), existing non SSO user ({$user->uuid}) with same email ({$user->email}) and email is not verified");
                    throw $failed('Email is not verified by the SSO provider');
                }
                $userWithSso = [$user, null];
            }
        }

        $now = Dates::now();
        $twofactorToken = null;
        if ($userWithSso === null) {
            if (! $this->config->isSsoSignupAllowed($infos->email)) {
                throw $failed($this->config->string('signups_domains_whitelist') === '' ? 'Signups are disabled. You will need an invitation' : 'Email domain not allowed');
            }
            if ($infos->emailVerified === null && ! $this->config->bool('sso_allow_unknown_email_verification')) {
                throw $failed("Your provider does not send email verification status.\nYou will need to change the server configuration (check `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`) to log in.");
            }
            if ($infos->emailVerified === false) {
                throw $failed('You need to verify your email with your provider before you can log in');
            }

            $user = User::new($infos->email, $infos->userName);
            $user->verified_at = $now;
            $user->save();
            $ssoUser = null;
            $loginDevice = $this->getDevice($user, ...$device);
        } else {
            [$user, $ssoUser] = $userWithSso;
            if (! $user->enabled) {
                throw ApiError::message('This user has been disabled', logMessage: "IP: {$ip}. Username: {$user->email}.", event: Event::USER_FAILED_LOG_IN);
            }

            $loginDevice = $this->getDevice($user, ...$device);
            $twofactorToken = $this->twofactorAuth($user, $loginDevice, $twoFactor, $clientId, $ip);

            if ($user->private_key === null) {
                // An invited user, whose stub account is completed now.
                $user->verified_at = $now;
                if ($infos->userName !== null) {
                    $user->name = $infos->userName;
                }
                $user->save();
            }

            if ($user->email !== $infos->email) {
                if ($this->config->mailEnabled()) {
                    Mail::sendSsoChangeEmail($infos->email);
                }
                logger()->info("User {$user->uuid} email changed in SSO provider from {$user->email} to {$infos->email}");
            }
        }

        $userId = $user->uuid;
        $tokens = $sso->redeem($loginDevice, $user, $clientId, $ssoUser, $auth, $infos);

        return $this->authenticatedResponse($user, $loginDevice, $tokens, $ip, $twofactorToken);
    }

    /**
     * GET /identity/connect/authorize: the clients start an SSO login here
     * and are sent on to the provider. A cookie binds the login to this
     * browser until the provider sends it back.
     *
     * @throws ApiError
     */
    public function authorize(Request $request): Response
    {
        // AuthorizeData: names without case, client_id and redirect_uri also without the underscore.
        $query = $request->server->get('QUERY_STRING');
        $pairs = FormUrlencoded::parse(is_string($query) ? $query : '');
        $field = static function (string ...$names) use ($pairs): ?string {
            foreach ($pairs as [$name, $value]) {
                if (in_array(strtolower($name), $names, true)) {
                    return $value;
                }
            }

            return null;
        };
        $clientId = $field('client_id', 'clientid');
        $redirectUri = $field('redirect_uri', 'redirecturi');
        $state = $field('state');
        $codeChallenge = $field('code_challenge');
        $codeChallengeMethod = $field('code_challenge_method');
        if ($clientId === null || $redirectUri === null || $state === null || $codeChallenge === null || $codeChallengeMethod === null) {
            // The query guard forwards; the web vault's catch-all finds nothing.
            throw new HttpStatus(WebController::webVaultEnabled($this->config) ? 404 : 422, 'Missing authorize data.');
        }
        if ($codeChallengeMethod !== 'S256') {
            throw ApiError::message('Unsupported code challenge method');
        }

        $bindingToken = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $url = (new Sso($this->config, $this->jwt))->authorizeUrl($state, $codeChallenge, $clientId, $redirectUri, hash('sha256', $bindingToken));

        $response = new Redirect($url, 307);
        $response->headers->setCookie(RocketCookie::session(self::SSO_BINDING_COOKIE, $bindingToken, $this->ssoCookiePath(),
            SsoAuth::EXPIRATION * 60, Secure::https($request), RocketCookie::SAMESITE_LAX));

        return $response;
    }

    /**
     * GET /identity/connect/oidc-signin: the provider sends the browser back
     * with a code, or with an error, which is then stored and passed on in
     * place of the code. The browser must be the one that started.
     *
     * @throws ApiError
     */
    public function oidcSignin(Request $request): Response
    {
        // oidcsignin needs code and state, oidcsignin_error state and error.
        $code = Query::first($request, 'code');
        $state = Query::first($request, 'state');
        $error = $code === null ? Query::first($request, 'error') : null;
        if ($state === null || ($code === null && $error === null)) {
            throw new HttpStatus(WebController::webVaultEnabled($this->config) ? 404 : 422, 'Missing code or error.');
        }

        $decoded = Sso::decodeState($state);
        $auth = SsoAuth::find($decoded) ?? throw ApiError::message('Cannot retrieve sso_auth for '.EscapeDebug::of($decoded));

        $cookie = $request->cookies->get(self::SSO_BINDING_COOKIE);
        $provided = is_string($cookie) ? hash('sha256', $cookie) : null;
        if ($auth->binding_hash === null || $provided === null || ! hash_equals($auth->binding_hash, $provided)) {
            throw ApiError::message('SSO session binding mismatch for '.EscapeDebug::of($decoded));
        }

        // The error is stored, and the encoded state stands in for the code.
        $code ??= $state;
        $auth->code_response = $code;
        $auth->setCodeResponseError($error, $error === null ? null : Query::first($request, 'error_description'));
        $auth->updated_at = Dates::now();
        $auth->save();

        // Url::parse gives an http(s) URL without path the path /.
        $redirectUri = $auth->redirect_uri;
        if (preg_match('#^https?://[^/?\#]+$#Di', $redirectUri) === 1) {
            $redirectUri .= '/';
        }
        $url = FormUrlencoded::appendPairs($redirectUri, [
            ['code', $code],
            ['state', $decoded],
            ['scope', AuthMethod::Sso->scope()],
            ['iss', $this->config->string('domain')],
        ]);

        $response = new Redirect($url, 307);
        $response->headers->setCookie(RocketCookie::removal(self::SSO_BINDING_COOKIE, $this->ssoCookiePath()));

        return $response;
    }

    private function ssoCookiePath(): string
    {
        return $this->config->string('domain_path').'/identity/connect/';
    }

    /**
     * @param  callable(string): ?string  $field
     */
    private function apiKeyLogin(string $clientId, string $clientSecret, string $scope, callable $field, string $ip, ?string &$userId): Response
    {
        $this->limiter->check('login', $ip);

        if ($scope === AuthMethod::OrgApiKey->scope()) {
            return $this->organizationApiKeyLogin($clientId, $clientSecret, $ip);
        }
        if ($scope !== AuthMethod::UserApiKey->scope()) {
            throw ApiError::message('Scope not supported');
        }

        // Like upstream, only the user API key logs in a device.
        $device = [];
        foreach (['device_identifier', 'device_name', 'device_type'] as $name) {
            $device[] = $field($name) ?? throw ApiError::message("{$name} cannot be blank");
        }

        $clientUserId = str_starts_with($clientId, 'user.') ? substr($clientId, strlen('user.')) : throw ApiError::message('Malformed client_id', logMessage: "IP: {$ip}.");
        $user = User::findByUuid($clientUserId) ?? throw ApiError::message('Invalid client_id', logMessage: "IP: {$ip}.");
        $userId = $user->uuid;

        if (! $user->enabled) {
            throw ApiError::message('This user has been disabled (API key login)', logMessage: "IP: {$ip}. Username: {$user->email}.", event: Event::USER_FAILED_LOG_IN);
        }
        // API key logins bypass 2FA.
        if (! $user->checkValidApiKey($clientSecret)) {
            throw ApiError::message('Incorrect client_secret', logMessage: "IP: {$ip}. Username: {$user->email}.", event: Event::USER_FAILED_LOG_IN);
        }

        $loginDevice = $this->getDevice($user, ...$device);
        $this->notifyNewDevice($user, $loginDevice, $ip);

        $claims = LoginClaims::default($loginDevice, $user, AuthMethod::UserApiKey, $clientId, $this->jwt);
        $loginDevice->save();

        // No refresh token: the CLI logs in again when the access token expires.
        return Json::response(Json::sorted([
            'access_token' => $claims->token($this->jwt),
            'expires_in' => $claims->expiresIn(),
            'token_type' => 'Bearer',
            'Key' => $user->akey,
            'PrivateKey' => $user->private_key,
            'Kdf' => $user->client_kdf_type,
            'KdfIterations' => $user->client_kdf_iter,
            'KdfMemory' => $user->client_kdf_memory,
            'KdfParallelism' => $user->client_kdf_parallelism,
            'ForcePasswordReset' => false,
            'scope' => AuthMethod::UserApiKey->scope(),
            'AccountKeys' => self::accountKeys($user),
            'UserDecryptionOptions' => self::decryptionOptions($user),
        ]));
    }

    private function authenticatedResponse(User $user, Device $device, AuthTokens $tokens, string $ip, ?string $twofactorToken = null): Response
    {
        $this->notifyNewDevice($user, $device, $ip);

        // register push device
        if (! $device->isNew()) {
            Push::registerDevice($device);
        }

        // Saved to track usage and the new status.
        $device->save();

        $result = [
            'access_token' => $tokens->accessToken(),
            'expires_in' => $tokens->expiresIn(),
            'token_type' => 'Bearer',
            'refresh_token' => $tokens->refreshToken(),
            'PrivateKey' => $user->private_key,
            'Kdf' => $user->client_kdf_type,
            'KdfIterations' => $user->client_kdf_iter,
            'KdfMemory' => $user->client_kdf_memory,
            'KdfParallelism' => $user->client_kdf_parallelism,
            'ForcePasswordReset' => false,
            'MasterPasswordPolicy' => MasterPasswordPolicy::forIdentity($user, $this->config),
            'scope' => $tokens->scope(),
            'AccountKeys' => self::accountKeys($user),
            'UserDecryptionOptions' => self::decryptionOptions($user),
        ];
        if ($user->akey !== '') {
            $result['Key'] = $user->akey;
        }
        if ($twofactorToken !== null) {
            $result['TwoFactorToken'] = $twofactorToken;
        }

        logger()->info("User {$user->email} logged in successfully. IP: {$ip}");

        return Json::response(Json::sorted($result));
    }

    /**
     * The device of the login, created (without touching updated_at) when it is new.
     */
    private function getDevice(User $user, string $identifier, string $name, string $type): Device
    {
        // iOS sends "iOS" here, the others a number; unknown means Unknown Browser.
        $atype = preg_match('/^[+-]?[0-9]+$/D', $type) && (int) $type >= -2_147_483_648 && (int) $type <= 2_147_483_647
            ? (int) $type : 14;

        $device = Device::findByUuidAndUser($identifier, $user->uuid);
        if ($device === null) {
            $device = Device::new($identifier, $user->uuid, $name, $atype);
            $device->save(['update_time' => false]);
        }

        return $device;
    }

    /**
     * identity::twofactor_auth: without methods the 2FA policy applies;
     * otherwise the client names a usable method (or the first) and sends
     * its code. A remembered device or the recovery code count as well. The
     * answer may carry a new token that remembers the device.
     *
     * @param  array{provider: ?int, token: ?string, remember: ?int}  $data
     *
     * @throws ApiError
     */
    private function twofactorAuth(User $user, Device $device, array $data, string $clientId, string $ip): ?string
    {
        $methods = TwoFactor::findByUser($user->uuid);
        if ($methods->isEmpty()) {
            OrgPolicy::enforceTwoFactorForUser($user, $user->uuid, $device->atype, $ip);

            return null;
        }

        TwoFactorIncomplete::markIncomplete($user->uuid, $device->uuid, $device->name, $device->atype, $ip);

        $providers = [];
        foreach ($methods as $method) {
            if ($method->enabled && TwoFactorController::isProviderUsable($method->atype, $method->data)) {
                $providers[] = $method->atype;
            }
        }
        if ($providers === []) {
            throw ApiError::message('No enabled and usable two factor providers are available for this account');
        }

        $selected = $data['provider'] ?? $providers[0];
        // Remember and the recovery code are no methods of their own.
        if (! in_array($selected, [TwoFactor::TYPE_REMEMBER, TwoFactor::TYPE_RECOVERY_CODE], true) && ! in_array($selected, $providers, true)) {
            throw ApiError::json($this->twofactorRequired($providers, $user, $clientId, $device->uuid), 'Invalid two factor provider');
        }
        // A blank code counts as none.
        $code = $data['token'];
        if ($code === null || trim($code) === '') {
            throw ApiError::json($this->twofactorRequired($providers, $user, $clientId, $device->uuid), '2FA token not provided');
        }

        $method = $methods->first(static fn (TwoFactor $method): bool => $method->atype === $selected && $method->enabled);
        $methodData = static fn (): string => ($method ?? throw ApiError::message("Two factor doesn't exist"))->data;

        match ($selected) {
            TwoFactor::TYPE_AUTHENTICATOR => AuthenticatorController::validateTotpCodeStr($user->uuid, $code, $methodData(), $ip),
            TwoFactor::TYPE_WEBAUTHN => WebauthnController::validateWebauthnLogin($user->uuid, $code),
            TwoFactor::TYPE_YUBIKEY => YubikeyController::validateYubikeyLogin($code, $methodData()),
            TwoFactor::TYPE_DUO => DuoOidc::validateLogin($user->email, $code, $clientId, $device->uuid),
            TwoFactor::TYPE_EMAIL => EmailController::validateEmailCodeStr($user->uuid, $code, $methodData(), $ip),
            TwoFactor::TYPE_REMEMBER => $this->checkRemembered($user, $device, $code, $providers, $clientId),
            TwoFactor::TYPE_RECOVERY_CODE => $this->recoverTwofactor($user, $device, $code, $ip),
            default => throw ApiError::message('Invalid two factor provider', event: Event::USER_FAILED_LOG_IN_2FA),
        };

        TwoFactorIncomplete::markComplete($user->uuid, $device->uuid);

        return ! $this->config->bool('disable_2fa_remember') && ($data['remember'] ?? 0) === 1 ? $device->refreshTwofactorRemember() : null;
    }

    /**
     * A remembered device logs in with its token; any other drops the token.
     *
     * @param  list<int>  $providers
     *
     * @throws ApiError
     */
    private function checkRemembered(User $user, Device $device, string $code, array $providers, string $clientId): void
    {
        $token = $device->twofactor_remember;
        if ($token !== null && ! $this->config->bool('disable_2fa_remember') && hash_equals($token, $code)) {
            try {
                $claims = $this->jwt->decode($code, JwtIssuer::TwoFactorRemember, fields: ['nbf' => 'int', 'exp' => 'int', 'iss' => 'string', 'sub' => 'string', 'user_uuid' => 'string']);
                if ($claims['sub'] === $device->uuid && $claims['user_uuid'] === $user->uuid) {
                    return;
                }
            } catch (ApiError) {
                // Expired or invalid: the prompt follows.
            }
        }

        if ($device->twofactor_remember !== null) {
            $device->deleteTwofactorRemember();
            // The error below would skip saving it later.
            $device->save();
        }

        throw ApiError::json($this->twofactorRequired($providers, $user, $clientId, $device->uuid), '2FA Remember token not provided or expired');
    }

    /**
     * The recovery code removes every method; spaces and case do not matter.
     *
     * @throws ApiError
     */
    private function recoverTwofactor(User $user, Device $device, string $code, string $ip): void
    {
        if (! $user->checkValidRecoveryCode(strtolower(trim(str_replace(' ', '', $code))))) {
            throw ApiError::message('Two-step token is invalid. Try again.', event: Event::USER_FAILED_LOG_IN_2FA);
        }

        TwoFactor::deleteAllByUser($user->uuid);
        // No device may keep skipping 2FA; this one would get its token back when saved.
        Device::clearTwofactorRememberByUser($user->uuid);
        $device->deleteTwofactorRemember();

        OrgPolicy::enforceTwoFactorForUser($user, $user->uuid, $device->atype, $ip);
        Event::logUser(Event::USER_RECOVERED_2FA, $user->uuid, $device->atype, $ip);

        if ($this->config->mailEnabled()) {
            try {
                Mail::sendRecoverTwofactor($user->email, $ip, Dates::now());
            } catch (ApiError $error) {
                logger()->error("Error sending two-step login recovered email: {$error->debugText()}");
            }
        }

        // Not needed without methods.
        $user->totp_recover = null;
        $user->save();
    }

    /**
     * json_err_twofactor: what a login without its second factor gets; some
     * methods add what the client needs for the prompt.
     *
     * @param  list<int>  $providers
     * @return array<string, mixed>
     *
     * @throws ApiError
     */
    private function twofactorRequired(array $providers, User $user, string $clientId, string $deviceIdentifier): array
    {
        $details = [];
        foreach ($providers as $provider) {
            $details[(string) $provider] = match ($provider) {
                TwoFactor::TYPE_EMAIL => Json::sorted(['Email' => EmailController::obscureEmail(EmailController::methodEmail(
                    (TwoFactor::findByUserAndType($user->uuid, TwoFactor::TYPE_EMAIL) ?? throw ApiError::message('No twofactor email registered'))->data,
                ))]),
                TwoFactor::TYPE_WEBAUTHN => $this->config->isWebauthn2faSupported() ? WebauthnController::generateWebauthnLogin($user->uuid) : null,
                TwoFactor::TYPE_DUO => ['AuthUrl' => DuoOidc::authUrl($user->email, $clientId, $deviceIdentifier)],
                TwoFactor::TYPE_YUBIKEY => ['Nfc' => YubikeyController::nfc(
                    (TwoFactor::findByUserAndType($user->uuid, TwoFactor::TYPE_YUBIKEY) ?? throw ApiError::message('No YubiKey devices registered'))->data,
                )],
                default => null,
            };
        }
        // Sorted as strings, and an object even with keys from 0 on.
        ksort($details, SORT_STRING);
        $object = new stdClass;
        foreach ($details as $key => $value) {
            $object->{(string) $key} = $value;
        }

        return [
            'MasterPasswordPolicy' => MasterPasswordPolicy::forIdentity($user, $this->config),
            'TwoFactorProviders' => array_map(strval(...), $providers),
            'TwoFactorProviders2' => $object,
            'error' => 'invalid_grant',
            'error_description' => 'Two factor required.',
        ];
    }

    /**
     * identity::organization_api_key_login: a token for the public API, for
     * one hour; no device, no refresh.
     */
    private function organizationApiKeyLogin(string $clientId, string $clientSecret, string $ip): Response
    {
        $orgId = str_starts_with($clientId, 'organization.') ? substr($clientId, strlen('organization.')) : throw ApiError::message('Malformed client_id', logMessage: "IP: {$ip}.");
        $apiKey = OrganizationApiKey::findByOrgUuid($orgId) ?? throw ApiError::message('Invalid client_id', logMessage: "IP: {$ip}.");
        if (! $apiKey->checkValidApiKey($clientSecret)) {
            throw ApiError::message('Incorrect client_secret', logMessage: "IP: {$ip}. Organization: {$apiKey->org_uuid}.");
        }

        // OrgApiKeyLoginJwtClaims
        $now = time();
        $token = $this->jwt->encode([
            'nbf' => $now,
            'exp' => $now + 3600,
            'iss' => $this->jwt->issuer(JwtIssuer::OrgApiKey),
            'sub' => $apiKey->uuid,
            'client_id' => "organization.{$apiKey->org_uuid}",
            'client_sub' => $apiKey->org_uuid,
            'scope' => [AuthMethod::OrgApiKey->scope()],
        ]);

        return Json::response(Json::sorted(['access_token' => $token, 'expires_in' => 3600, 'token_type' => 'Bearer', 'scope' => AuthMethod::OrgApiKey->scope()]));
    }

    /**
     * Mail about a login from a new device; failing it only stops the login with REQUIRE_DEVICE_EMAIL.
     */
    private function notifyNewDevice(User $user, Device $device, string $ip): void
    {
        if (! $this->config->mailEnabled() || ! $device->isNew()) {
            return;
        }

        try {
            Mail::sendNewDeviceLoggedIn($user->email, $ip, Dates::now(), $device);
        } catch (ApiError $error) {
            logger()->error("Error sending new device email: {$error->getMessage()}");
            if ($this->config->bool('require_device_email')) {
                throw ApiError::message('Could not send login notification email. Please contact your administrator.', event: Event::USER_FAILED_LOG_IN);
            }
        }
    }

    /**
     * Send another verification mail now and then while the email is unverified.
     */
    private function remindToVerify(User $user): void
    {
        $now = Dates::now();
        if ($user->last_verifying_at !== null
            && $now->getTimestamp() - $user->last_verifying_at->getTimestamp() <= $this->config->int('signups_verify_resend_time')) {
            return;
        }

        $limit = $this->config->int('signups_verify_resend_limit');
        if ($limit !== 0 && $user->login_verify_count >= $limit) {
            return;
        }

        $user->last_verifying_at = $now;
        $user->login_verify_count++;
        try {
            $user->save();
        } catch (ApiError $error) {
            logger()->error("Error updating user: {$error->getMessage()}");
        }

        try {
            Mail::sendVerifyEmail($user->email, $user->uuid);
        } catch (ApiError $error) {
            logger()->error("Error auto-sending email verification email: {$error->getMessage()}");
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function accountKeys(User $user): ?array
    {
        if ($user->private_key === null) {
            return null;
        }

        return Json::sorted([
            'publicKeyEncryptionKeyPair' => [
                'wrappedPrivateKey' => $user->private_key,
                'publicKey' => $user->public_key,
                'Object' => 'publicKeyEncryptionKeyPair',
            ],
            'Object' => 'privateKeys',
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private static function decryptionOptions(User $user): array
    {
        $hasMasterPassword = $user->password_hash !== '';

        return Json::sorted([
            'HasMasterPassword' => $hasMasterPassword,
            'MasterPasswordUnlock' => $hasMasterPassword ? [
                'Kdf' => [
                    'KdfType' => $user->client_kdf_type,
                    'Iterations' => $user->client_kdf_iter,
                    'Memory' => $user->client_kdf_memory,
                    'Parallelism' => $user->client_kdf_parallelism,
                ],
                // Named inconsistently upstream; clients move to the wrapped variant.
                'MasterKeyEncryptedUserKey' => $user->akey,
                'MasterKeyWrappedUserKey' => $user->akey,
                'Salt' => $user->email,
            ] : null,
            'Object' => 'userDecryptionOptions',
        ]);
    }

    private function prelogin(Request $request): Response
    {
        $email = Body::json($request)->string('email');

        return $this->accounts->prelogin($email, ClientIp::resolve($request, $this->config));
    }
}
