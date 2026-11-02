<?php

namespace App\Http\Controllers;

use App\Auth\ClientIp;
use App\Auth\Headers;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\MasterPasswordPolicy;
use App\Auth\RsaKeys;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Controllers\TwoFactor\EmailController;
use App\Http\Data\AuthenticationData;
use App\Http\Data\Body;
use App\Http\Data\CipherData;
use App\Http\Data\Fields;
use App\Http\Data\KdfData;
use App\Http\Data\NumberOrString;
use App\Http\Data\PasswordOrOtpData;
use App\Http\Data\Query;
use App\Http\Data\RegisterData;
use App\Http\Data\SendData;
use App\Http\Data\UnlockData;
use App\Http\EmptyResponse;
use App\Http\HttpStatus;
use App\Http\Json;
use App\Mail\Mail;
use App\Models\AuthRequest;
use App\Models\Cipher;
use App\Models\Device;
use App\Models\EmergencyAccess;
use App\Models\Event;
use App\Models\Folder;
use App\Models\Invitation;
use App\Models\Membership;
use App\Models\Organization;
use App\Models\OrgPolicy;
use App\Models\Send;
use App\Models\User;
use App\Notifications\Notify;
use App\Support\CheckedInt;
use App\Support\Dates;
use App\Support\Push;
use App\Support\Random;
use App\Support\RateLimiter;
use App\Support\UpdateType;
use App\Support\Uuid;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Throwable;

/**
 * src/api/core/accounts.rs
 */
final readonly class AccountsController
{
    /**
     * sso::FAKE_SSO_IDENTIFIER and admin::FAKE_ADMIN_UUID, which name no organization.
     */
    private const string FAKE_SSO_IDENTIFIER = '00000000-01DC-01DC-01DC-000000000000';

    private const string FAKE_ADMIN_UUID = '00000000-0000-0000-0000-000000000000';

    private const int KDF_PBKDF2 = 0;

    private const int KDF_ARGON2ID = 1;

    /**
     * Settings for unknown emails, the default twice for more weight (like upstream).
     */
    private const array UNKNOWN_EMAIL_KDF = [
        [User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, null, null],
        [User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, null, null],
        [self::KDF_PBKDF2, 100_000, null, null],
        [self::KDF_PBKDF2, 5_000, null, null],
        [self::KDF_ARGON2ID, 3, 64, 4],
        [self::KDF_ARGON2ID, 6, 32, 4],
    ];

    public function __construct(
        private Config $config,
        private Jwt $jwt,
        private RsaKeys $keys,
        private RateLimiter $limiter,
        private Notify $nt,
    ) {}

    /**
     * accounts::prelogin: the KDF settings of an email. An unknown email gets
     * settings derived from it, the same on every request.
     */
    public function prelogin(string $email, string $ip): Response
    {
        $this->limiter->check('unauthenticated', $ip);

        $email = mb_strtolower(trim($email));
        $user = User::findByMail($email);
        [$type, $iterations, $memory, $parallelism] = $user !== null
            ? [$user->client_kdf_type, $user->client_kdf_iter, $user->client_kdf_memory, $user->client_kdf_parallelism]
            : self::UNKNOWN_EMAIL_KDF[$this->keys->preloginKdfIndex($email, count(self::UNKNOWN_EMAIL_KDF))];

        return Json::response(Json::sorted([
            'kdf' => $type,
            'kdfIterations' => $iterations,
            'kdfMemory' => $memory,
            'kdfParallelism' => $parallelism,
            'kdfSettings' => [
                'iterations' => $iterations,
                'kdfType' => $type,
                'memory' => $memory,
                'parallelism' => $parallelism,
            ],
            'salt' => null,
        ]));
    }

    /**
     * accounts::register: create the user, or complete an invited one.
     *
     * @throws ApiError
     */
    public function register(RegisterData $data): Response
    {
        $email = mb_strtolower($data->email);
        $name = null;
        $pendingEmergencyAccess = false;

        if ($data->unprocessable()) {
            throw ApiError::message('Unexpected RegisterData format', 422);
        }

        // The verification tokens decide which kind of registration this is.
        $tokens = [
            $data->emailVerificationToken !== null,
            $data->acceptEmergencyAccessId !== null,
            $data->acceptEmergencyAccessInviteToken !== null,
            $data->organizationUserId !== null,
            $data->orgInviteToken !== null,
        ];
        if ($tokens === [true, false, false, false, false]) {
            // Normal registration
            $claims = $this->jwt->decode((string) $data->emailVerificationToken, JwtIssuer::RegisterVerify);
            if (($claims['sub'] ?? null) !== $data->email) {
                throw ApiError::message('Email verification token does not match email');
            }
            $name = is_string($claims['name'] ?? null) ? $claims['name'] : null;
            $emailVerified = ($claims['verified'] ?? false) === true;
        } elseif ($tokens === [false, true, true, false, false]) {
            // Emergency access registration
            if (! $this->config->bool('emergency_access_allowed')) {
                throw ApiError::message('Emergency access is not enabled.');
            }
            $claims = $this->jwt->decode((string) $data->acceptEmergencyAccessInviteToken, JwtIssuer::EmergencyAccessInvite, fields: Jwt::EMERGENCY_ACCESS_INVITE_CLAIMS);
            if (($claims['email'] ?? null) !== $data->email) {
                throw ApiError::message('Claim email does not match email');
            }
            if (($claims['emer_id'] ?? null) !== $data->acceptEmergencyAccessId) {
                throw ApiError::message('Claim emer_id does not match accept_emergency_access_id');
            }
            $pendingEmergencyAccess = true;
            $emailVerified = true;
        } elseif ($tokens === [false, false, false, true, true]) {
            // Organization invitation
            $claims = $this->jwt->decode((string) $data->orgInviteToken, JwtIssuer::Invite, fields: Jwt::INVITE_CLAIMS);
            if (($claims['email'] ?? null) !== $data->email) {
                throw ApiError::message('Claim email does not match email');
            }
            if (($claims['member_id'] ?? null) !== $data->organizationUserId) {
                throw ApiError::message('Claim org_user_id does not match organization_user_id');
            }
            $emailVerified = true;
        } else {
            throw ApiError::message('Registration is missing required parameters');
        }

        // Like upstream Bitwarden; long names also make the tokens too large.
        if ($name !== null && strlen($name) > 50) {
            throw ApiError::message('The field Name must be a string with a maximum length of 50.');
        }

        // Checked before the invitation is used, so that a failure can be retried.
        $passwordHint = self::cleanPasswordHint($data->masterPasswordHint);
        $this->enforcePasswordHintSetting($passwordHint);

        $user = User::findByMail($email);
        if ($user !== null) {
            if ($user->password_hash !== '') {
                throw ApiError::message('Registration not allowed or user already exists');
            }

            if ($data->orgInviteToken !== null) {
                $claims = $this->jwt->decode($data->orgInviteToken, JwtIssuer::Invite, fields: Jwt::INVITE_CLAIMS);
                if (($claims['email'] ?? null) !== $email) {
                    throw ApiError::message('Registration email does not match invite email');
                }
                // A valid invitation verifies the email.
                $emailVerified = true;
            } elseif (Invitation::take($email)) {
                Membership::acceptUserInvitations($user->uuid);
            } elseif (! $this->config->isSignupAllowed($email)
                && ! ($this->config->bool('emergency_access_allowed') && EmergencyAccess::findInvitedByGranteeEmail($email) !== null)) {
                throw ApiError::message('Registration not allowed or user already exists');
            }
        } elseif (Invitation::take($email) || $this->config->isSignupAllowed($email) || $pendingEmergencyAccess) {
            // The invitation comes first: the admin can invite anyone, whatever the signup rules.
            $user = User::new($email);
        } else {
            throw ApiError::message('Registration not allowed or user already exists');
        }

        // No invitation may linger.
        Invitation::take($email);

        self::setKdfData($user, $data->kdf);
        $user->setPassword($data->hash, $data->key, resetSecurityStamp: true, allowNextRoute: null);
        $user->password_hint = $passwordHint;

        if ($name !== null) {
            $user->name = $name;
        }
        if ($data->keys !== null) {
            $user->private_key = $data->keys['encryptedPrivateKey'];
            $user->public_key = $data->keys['publicKey'];
        }
        if ($emailVerified) {
            $user->verified_at = Dates::now();
        }

        if ($this->config->mailEnabled()) {
            try {
                if ($this->config->bool('signups_verify') && ! $emailVerified) {
                    $user->last_verifying_at = $user->created_at;
                    Mail::sendWelcomeMustVerify($user->email, $user->uuid);
                } else {
                    Mail::sendWelcome($user->email);
                }
            } catch (Throwable $error) {
                logger()->error("Error sending welcome email: {$error->getMessage()}");
            }

            // Before the user is saved: a new user's row does not exist yet, and the error is ignored.
            if ($emailVerified && $this->isEmail2faRequired($data->organizationUserId)) {
                try {
                    EmailController::activateEmail2fa($user);
                } catch (ApiError) {
                    // Ignored like upstream.
                }
            }
        }

        $user->save();

        // Open emergency access invitations are accepted right away.
        if (! $this->config->mailEnabled() && $this->config->bool('emergency_access_allowed')) {
            foreach (EmergencyAccess::findAllInvitedByGranteeEmail($user->email) as $invite) {
                try {
                    $invite->acceptInvite($user->uuid, $user->email);
                } catch (ApiError) {
                    // Like `.ok()`: ignored.
                }
            }
        }

        return Json::response(['object' => 'registerFinish']);
    }

    /**
     * GET /api/accounts/profile
     */
    public function profile(Headers $headers): Response
    {
        return Json::response($headers->user->toApi());
    }

    /**
     * PUT /api/accounts/profile
     */
    public function putProfile(Headers $headers, Request $request): Response
    {
        return $this->postProfile($headers, $request);
    }

    /**
     * POST /api/accounts/profile: only the name can change; the culture is always en-US.
     */
    public function postProfile(Headers $headers, Request $request): Response
    {
        $name = Body::json($request)->string('name');

        // Like upstream Bitwarden; long names also make the tokens too large.
        if (strlen($name) > 50) {
            throw ApiError::message('The field Name must be a string with a maximum length of 50.');
        }

        $user = $headers->user;
        $user->name = $name;
        $user->save();

        return Json::response($user->toApi());
    }

    /**
     * PUT /api/accounts/avatar: a color like #a1b2c3, or none.
     */
    public function putAvatar(Headers $headers, Request $request): Response
    {
        $color = Body::json($request)->optionalString('avatarColor');
        if ($color !== null && strlen($color) !== 7) {
            throw ApiError::message('The field AvatarColor must be a HTML/Hex color code with a length of 7 characters');
        }

        $user = $headers->user;
        $user->avatar_color = $color;
        $user->save();

        return Json::response($user->toApi());
    }

    /**
     * GET /api/users/{user_id}/public-key
     */
    public function getPublicKeys(Headers $headers, Request $request, string $userId): Response
    {
        $user = User::findByUuid(Uuid::parameter($request, $userId));
        if ($user === null) {
            throw ApiError::message("User doesn't exist", 404);
        }
        if ($user->public_key === null) {
            throw ApiError::message('User has no public_key', 404);
        }

        return Json::response(Json::sorted([
            'userId' => $user->uuid,
            'publicKey' => $user->public_key,
            'object' => 'userKey',
        ]));
    }

    /**
     * GET /api/accounts/keys: the SDK reads a 404 as "no key pair yet".
     */
    public function getKeys(Headers $headers): Response
    {
        $user = $headers->user;
        if ($user->private_key === null || $user->public_key === null) {
            throw ApiError::message('User has no key pair', 404);
        }

        return Json::response(Json::sorted([
            'key' => $user->akey === '' ? null : $user->akey,
            'publicKey' => $user->public_key,
            'privateKey' => $user->private_key,
            'accountKeys' => $user->accountKeysJson(),
            'object' => 'keys',
        ]));
    }

    /**
     * POST /api/accounts/keys: the key pair can only be set once.
     */
    public function postKeys(Headers $headers, Request $request): Response
    {
        $body = Body::json($request);
        $encryptedPrivateKey = $body->string('encryptedPrivateKey');
        $publicKey = $body->string('publicKey');

        $user = $headers->user;
        if ($user->private_key !== null || $user->public_key !== null) {
            throw ApiError::message('User has existing keypair');
        }

        $user->private_key = $encryptedPrivateKey;
        $user->public_key = $publicKey;
        $user->save();

        return Json::response(Json::sorted([
            'privateKey' => $user->private_key,
            'publicKey' => $user->public_key,
            'object' => 'keys',
        ]));
    }

    /**
     * GET /api/accounts/revision-date: milliseconds since the epoch.
     */
    public function revisionDate(Headers $headers): Response
    {
        return Json::response((int) $headers->user->updated_at->format('Uv'));
    }

    /**
     * Validate and apply the client's KDF settings.
     *
     * @throws ApiError
     */
    public static function setKdfData(User $user, KdfData $data): void
    {
        if ($data->kdf === self::KDF_PBKDF2 && $data->kdfIterations < 100_000) {
            throw ApiError::message('PBKDF2 KDF iterations must be at least 100000.');
        }

        if ($data->kdf === self::KDF_ARGON2ID) {
            if ($data->kdfIterations < 1) {
                throw ApiError::message('Argon2 KDF iterations must be at least 1.');
            }
            if ($data->kdfMemory === null) {
                throw ApiError::message('Argon2 memory parameter is required.');
            }
            if ($data->kdfMemory < 15 || $data->kdfMemory > 1024) {
                throw ApiError::message('Argon2 memory must be between 15 MB and 1024 MB.');
            }
            $user->client_kdf_memory = $data->kdfMemory;
            if ($data->kdfParallelism === null) {
                throw ApiError::message('Argon2 parallelism parameter is required.');
            }
            if ($data->kdfParallelism < 1 || $data->kdfParallelism > 16) {
                throw ApiError::message('Argon2 parallelism must be between 1 and 16.');
            }
            $user->client_kdf_parallelism = $data->kdfParallelism;
        } else {
            $user->client_kdf_memory = null;
            $user->client_kdf_parallelism = null;
        }

        $user->client_kdf_iter = $data->kdfIterations;
        $user->client_kdf_type = $data->kdf;
    }

    /**
     * Raise the server-side hash iterations to PASSWORD_ITERATIONS at login.
     *
     * @throws ApiError
     */
    public function kdfUpgrade(User $user, string $passwordHash): void
    {
        $iterations = $this->config->int('password_iterations');
        if ($user->password_iterations >= $iterations) {
            return;
        }

        $user->password_iterations = $iterations;
        $user->setPassword($passwordHash, null, resetSecurityStamp: false, allowNextRoute: null);

        try {
            $user->save();
        } catch (ApiError $error) {
            logger()->error("Error updating user: {$error->getMessage()}");
        }
    }

    /**
     * Blank hints count as none.
     */
    public static function cleanPasswordHint(?string $hint): ?string
    {
        $hint = $hint === null ? null : trim($hint);

        return $hint === '' ? null : $hint;
    }

    /**
     * @throws ApiError
     */
    public function enforcePasswordHintSetting(?string $hint): void
    {
        if ($hint !== null && ! $this->config->bool('password_hints_allowed')) {
            throw ApiError::message('Password hints have been disabled by the administrator. Remove the hint and try again.');
        }
    }

    /**
     * is_email_2fa_required: for everyone, or for the members of an
     * organization with the 2FA policy.
     */
    private function isEmail2faRequired(?string $memberId): bool
    {
        if (! $this->config->bool('_enable_email_2fa')) {
            return false;
        }
        if ($this->config->bool('email_2fa_enforce_on_verified_invite')) {
            return true;
        }
        $member = $memberId === null ? null : Membership::findByUuid($memberId);

        return $member !== null && (OrgPolicy::findByOrgAndType($member->org_uuid, OrgPolicy::TYPE_TWO_FACTOR_AUTHENTICATION)->enabled ?? false);
    }

    /**
     * POST /api/accounts/set-password: the first password of an account made
     * by an invitation or SSO, which may accept the organization's invitation.
     */
    public function postSetPassword(Headers $headers, Request $request): Response
    {
        $body = Body::json($request);
        $kdf = KdfData::fromFields($body);
        $key = $body->string('key');
        $keysFields = $body->optionalObject('keys');
        $keys = $keysFields === null ? null : [$keysFields->string('encryptedPrivateKey'), $keysFields->string('publicKey')];
        $passwordHash = $body->string('masterPasswordHash');
        $hint = $body->optionalString('masterPasswordHint');
        $orgIdentifier = $body->optionalString('orgIdentifier');
        $user = $headers->user;

        if ($user->private_key !== null || $user->password_hash !== '') {
            throw ApiError::message('Account already initialized, cannot set password');
        }
        // Checked first, so that a failure can be retried without losing the invitation.
        $hint = self::cleanPasswordHint($hint);
        $this->enforcePasswordHintSetting($hint);
        self::setKdfData($user, $kdf);
        // The revision date may still be asked with the old stamp.
        $user->setPassword($passwordHash, $key, false, ['revision_date']);
        $user->password_hint = $hint;
        if ($keys !== null) {
            [$user->private_key, $user->public_key] = $keys;
        }

        if ($orgIdentifier !== null && $orgIdentifier !== self::FAKE_SSO_IDENTIFIER && $orgIdentifier !== self::FAKE_ADMIN_UUID) {
            $org = Organization::findByUuid($orgIdentifier) ?? throw ApiError::message('Failed to retrieve the associated organization');
            $membership = Membership::findByUserAndOrg($user->uuid, $org->uuid) ?? throw ApiError::message('Failed to retrieve the invitation');
            OrganizationsController::acceptOrgInvite($user, $membership, null);
        }

        if ($this->config->mailEnabled()) {
            Mail::sendWelcome(strtolower($user->email));
        } else {
            Membership::acceptUserInvitations($user->uuid);
        }
        Event::logUser(Event::USER_CHANGED_PASSWORD, $user->uuid, $headers->device->atype, $headers->ip);
        $user->save();

        return Json::response(['object' => 'set-password']);
    }

    /**
     * POST /api/accounts/password: a new master password, as authentication
     * and unlock data or in the older flat form. Other sessions end.
     */
    public function postPassword(Headers $headers, Request $request): EmptyResponse
    {
        $body = Body::json($request);
        $passwordHash = $body->string('masterPasswordHash');
        $hint = $body->optionalString('masterPasswordHint');
        $authenticationFields = $body->optionalObject('authenticationData');
        $authentication = $authenticationFields === null ? null : AuthenticationData::fromFields($authenticationFields);
        $unlockFields = $body->optionalObject('unlockData');
        $unlock = $unlockFields === null ? null : UnlockData::fromFields($unlockFields);
        $newHash = $body->optionalString('newMasterPasswordHash');
        $key = $body->optionalString('key');
        $user = $headers->user;

        if (! $user->checkValidPassword($passwordHash)) {
            throw ApiError::message('Invalid password');
        }
        Event::logUser(Event::USER_CHANGED_PASSWORD, $user->uuid, $headers->device->atype, $headers->ip);

        if ($unlock !== null && $authentication !== null) {
            if (! $authentication->kdf->equals($unlock->kdf)) {
                throw ApiError::message('KDF settings must be equal for authentication and unlock');
            }
            if ($user->email !== $authentication->salt || $user->email !== $unlock->salt) {
                throw ApiError::message('Invalid master password salt');
            }
            [$newHash, $key] = [$authentication->masterPasswordAuthenticationHash, $unlock->masterKeyWrappedUserKey];
        } elseif ($newHash === null || $key === null) {
            throw ApiError::message('Invalid request!');
        }

        $user->password_hint = self::cleanPasswordHint($hint);
        $this->enforcePasswordHintSetting($user->password_hint);
        // The client that asked may finish what it does with the old stamp.
        $user->setPassword($newHash, $key, true, ['post_rotatekey', 'get_contacts', 'get_public_keys', 'get_api_webauthn']);
        try {
            $user->save();
        } finally {
            // Prevent logging out the client where the user requested this endpoint from.
            $this->nt->sendLogout($user, $headers->device);
        }

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/kdf: new KDF settings, and the password hash and key made with them.
     */
    public function postKdf(Headers $headers, Request $request): EmptyResponse
    {
        $body = Body::json($request);
        $authentication = AuthenticationData::fromFields($body->object('authenticationData'));
        $unlock = UnlockData::fromFields($body->object('unlockData'));
        $passwordHash = $body->string('masterPasswordHash');
        $user = $headers->user;

        if (! $user->checkValidPassword($passwordHash)) {
            throw ApiError::message('Invalid password');
        }
        $authentication->check($user, $unlock);
        self::setKdfData($user, $unlock->kdf);
        $user->setPassword($authentication->masterPasswordAuthenticationHash, $unlock->masterKeyWrappedUserKey, true, null);
        try {
            $user->save();
        } finally {
            $this->nt->sendLogout($user, $headers->device);
        }

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/key-management/rotate-user-account-keys: everything
     * encrypted with the user key, encrypted with a new one. All of it must
     * be there; the KDF, the email and the key pair stay.
     */
    public function postRotatekey(Headers $headers, Request $request, CiphersController $ciphers): EmptyResponse
    {
        $body = Body::json($request);
        $unlockData = $body->object('accountUnlockData');
        $emergencyAccess = array_map(static fn (Fields $f): array => [$f->string('id'), $f->string('keyEncrypted')], $unlockData->objectList('emergencyAccessUnlockData'));
        $masterPassword = $unlockData->object('masterPasswordUnlockData');
        $unlock = [
            'kdfType' => $masterPassword->int('kdfType'),
            'kdfIterations' => $masterPassword->int('kdfIterations'),
            'kdfParallelism' => $masterPassword->optionalInt('kdfParallelism'),
            'kdfMemory' => $masterPassword->optionalInt('kdfMemory'),
            'email' => $masterPassword->string('email'),
            'masterKeyAuthenticationHash' => $masterPassword->string('masterKeyAuthenticationHash'),
            'masterKeyEncryptedUserKey' => $masterPassword->string('masterKeyEncryptedUserKey'),
        ];
        $resetPassword = array_map(static fn (Fields $f): array => [$f->string('organizationId'), $f->string('resetPasswordKey')],
            $unlockData->objectList('organizationAccountRecoveryUnlockData'));
        $accountKeys = $body->object('accountKeys');
        $privateKey = $accountKeys->string('userKeyEncryptedAccountPrivateKey');
        $publicKey = $accountKeys->string('accountPublicKey');
        $accountData = $body->object('accountData');
        $cipherData = array_map(CipherData::fromFields(...), $accountData->objectList('ciphers'));
        // A bug of the 2024.3 clients adds folders without an id.
        $folders = array_map(static fn (Fields $f): array => [$f->optionalNonEmptyString('id'), $f->string('name')], $accountData->objectList('folders'));
        $sends = array_map(SendData::fromFields(...), $accountData->objectList('sends'));
        $oldHash = $body->string('oldMasterKeyAuthenticationHash');
        $user = $headers->user;

        if (! $user->checkValidPassword($oldHash)) {
            throw ApiError::message('Invalid password');
        }
        // Nothing is changed when one cipher is invalid.
        $ciphers->validateCipherData($cipherData);

        $existingCiphers = Cipher::findOwnedByUser($user->uuid)->keyBy('uuid');
        $existingFolders = Folder::findByUser($user->uuid)->keyBy('uuid');
        $existingEmergencyAccess = EmergencyAccess::findAllConfirmedByGrantorUuid($user->uuid)->keyBy('uuid');
        // Only the reset password keys that are set are rotated.
        $existingMemberships = Membership::findByUser($user->uuid)->filter(static fn (Membership $m): bool => $m->reset_password_key !== null)->keyBy('org_uuid');
        $existingSends = Send::findByUser($user->uuid)->keyBy('uuid');

        // validate_keydata
        if ($user->client_kdf_type !== $unlock['kdfType'] || $user->client_kdf_iter !== $unlock['kdfIterations'] || $user->client_kdf_memory !== $unlock['kdfMemory']
            || $user->client_kdf_parallelism !== $unlock['kdfParallelism'] || $user->email !== $unlock['email']) {
            throw ApiError::message('Changing the kdf variant or email is not supported during key rotation');
        }
        if ($user->public_key !== $publicKey) {
            throw ApiError::message('Changing the asymmetric keypair is not possible during key rotation');
        }
        $personal = array_values(array_filter($cipherData, static fn (CipherData $c): bool => $c->organizationId === null));
        if (self::missingIds($existingCiphers->keys()->all(), array_map(static fn (CipherData $c): ?string => $c->id, $personal))) {
            throw ApiError::message('All existing ciphers must be included in the rotation');
        }
        if (self::missingIds($existingFolders->keys()->all(), array_column($folders, 0))) {
            throw ApiError::message('All existing folders must be included in the rotation');
        }
        if (self::missingIds($existingEmergencyAccess->keys()->all(), array_column($emergencyAccess, 0))) {
            throw ApiError::message('All existing emergency access keys must be included in the rotation');
        }
        if (self::missingIds($existingMemberships->keys()->all(), array_column($resetPassword, 0))) {
            throw ApiError::message('All existing reset password keys must be included in the rotation');
        }
        if (self::missingIds($existingSends->keys()->all(), array_map(static fn (SendData $d): ?string => $d->id, $sends))) {
            throw ApiError::message('All existing sends must be included in the rotation');
        }

        foreach ($folders as [$id, $name]) {
            if ($id !== null) {
                $folder = $existingFolders->get($id) ?? throw ApiError::message("Folder doesn't exist");
                $folder->name = $name;
                $folder->save();
            }
        }
        foreach ($emergencyAccess as [$id, $keyEncrypted]) {
            $access = $existingEmergencyAccess->get($id) ?? throw ApiError::message("Emergency access doesn't exist or is not owned by the user");
            $access->key_encrypted = $keyEncrypted;
            $access->save();
        }
        foreach ($resetPassword as [$orgId, $resetPasswordKey]) {
            $membership = $existingMemberships->get($orgId) ?? throw ApiError::message("Reset password doesn't exist");
            $membership->reset_password_key = $resetPasswordKey;
            $membership->save();
        }
        foreach ($sends as $data) {
            $send = ($data->id === null ? null : $existingSends->get($data->id)) ?? throw ApiError::message("Send doesn't exist");
            // Like upstream, only the key changes.
            $send->akey = $data->key;
            $send->save();
        }
        foreach ($personal as $data) {
            $cipher = ($data->id === null ? null : $existingCiphers->get($data->id)) ?? throw ApiError::message("Cipher doesn't exist");
            // No sync notifications: the sessions end with the new stamp anyway.
            $ciphers->updateCipherFromData($cipher, $data, $headers, UpdateType::None);
        }

        $user->private_key = $privateKey;
        $user->setPassword($unlock['masterKeyAuthenticationHash'], $unlock['masterKeyEncryptedUserKey'], true, null);
        try {
            $user->save();
        } finally {
            // Prevent logging out the client where the user requested this endpoint from.
            $this->nt->sendLogout($user, $headers->device);
        }

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/key-management/user-key-id: set once.
     */
    public function postUserKey(Headers $headers, Request $request): EmptyResponse
    {
        $keyId = Body::json($request)->string('userKeyId');
        $user = $headers->user;
        if ($user->key_id !== null) {
            throw ApiError::message('Unexpected data', 422);
        }
        $user->key_id = $keyId;
        $user->save();

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/security-stamp: every session and device is signed out.
     */
    public function postSstamp(Headers $headers, Request $request): EmptyResponse
    {
        $data = PasswordOrOtpData::fromFields(Body::json($request));
        $user = $headers->user;
        $data->validate($user, true, $this->config);

        $user->resetSecurityStamp();
        try {
            $user->save();
        } finally {
            $this->nt->sendLogout($user, null);
            Device::deleteAllByUser($user->uuid);
        }

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/email-token: a code to the new address, which must be free.
     */
    public function postEmailToken(Headers $headers, Request $request): EmptyResponse
    {
        if (! $this->config->bool('email_change_allowed')) {
            throw ApiError::message('Email change is not allowed.');
        }
        $body = Body::json($request);
        $passwordHash = $body->string('masterPasswordHash');
        $newEmail = $body->string('newEmail');
        $user = $headers->user;

        if (! $user->checkValidPassword($passwordHash)) {
            throw ApiError::message('Invalid password');
        }

        $existing = User::findByMail($newEmail);
        if ($existing !== null) {
            if ($this->config->mailEnabled()) {
                // An invited user may want to delete the temporary account; a registered one hears of the attempt.
                $kind = $existing->password_hash === '' ? 'invited' : 'existing';
                try {
                    $kind === 'invited' ? Mail::sendChangeEmailInvited($newEmail, $user->email) : Mail::sendChangeEmailExisting($newEmail, $user->email);
                } catch (ApiError $error) {
                    logger()->error("Error sending change-email-{$kind} email: {$error->debugText()}");
                }
            }
            throw ApiError::message('Email already in use');
        }
        if (! $this->config->isEmailDomainAllowed($newEmail)) {
            throw ApiError::message('Email domain not allowed');
        }

        $token = Random::numeric(6);
        if ($this->config->mailEnabled()) {
            try {
                Mail::sendChangeEmail($newEmail, $token);
            } catch (ApiError $error) {
                logger()->error("Error sending change-email email: {$error->debugText()}");
            }
        }

        $user->email_new = $newEmail;
        $user->email_new_token = $token;
        $user->save();

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/email: the pending address, with the mailed code;
     * the password hash and key are made for the new address.
     */
    public function postEmail(Headers $headers, Request $request): EmptyResponse
    {
        if (! $this->config->bool('email_change_allowed')) {
            throw ApiError::message('Email change is not allowed.');
        }
        $body = Body::json($request);
        $passwordHash = $body->string('masterPasswordHash');
        $newEmail = $body->string('newEmail');
        $key = $body->string('key');
        $newHash = $body->string('newMasterPasswordHash');
        $token = NumberOrString::optional($body, 'token') ?? throw new HttpStatus(422, 'Missing field `token`.');
        $user = $headers->user;

        if (! $user->checkValidPassword($passwordHash)) {
            throw ApiError::message('Invalid password');
        }
        if (User::findByMail($newEmail) !== null) {
            throw ApiError::message('Email already in use');
        }
        if ($user->email_new === null) {
            throw ApiError::message('No email change pending');
        }
        if ($user->email_new !== $newEmail) {
            throw ApiError::message('Email change mismatch');
        }

        // The code is only checked when it was mailed.
        if ($this->config->mailEnabled()) {
            if ($user->email_new_token === null) {
                throw ApiError::message('No email change pending');
            }
            if ($user->email_new_token !== (string) $token) {
                throw ApiError::message('Token mismatch');
            }
            $user->verified_at = Dates::now();
        } else {
            $user->verified_at = null;
        }

        $user->email = $newEmail;
        $user->email_new = null;
        $user->email_new_token = null;
        $user->setPassword($newHash, $key, true, null);
        try {
            $user->save();
        } finally {
            $this->nt->sendLogout($user, null);
        }

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/verify-email: a new verification link.
     */
    public function postVerifyEmail(Headers $headers): EmptyResponse
    {
        if (! $this->config->mailEnabled()) {
            throw ApiError::message('Cannot verify email address');
        }
        try {
            Mail::sendVerifyEmail($headers->user->email, $headers->user->uuid);
        } catch (ApiError $error) {
            logger()->error("Error sending verify_email email: {$error->debugText()}");
        }

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/verify-email-token: the link of the verification mail.
     */
    public function postVerifyEmailToken(Request $request): EmptyResponse
    {
        $body = Body::json($request);
        $userId = $body->string('userId');
        $token = $body->string('token');

        $user = User::findByUuid($userId) ?? throw ApiError::message("User doesn't exist");
        if (! $this->claimsSubject($token, JwtIssuer::VerifyEmail, $user->uuid)) {
            throw ApiError::message('Invalid claim');
        }
        $user->verified_at = Dates::now();
        $user->last_verifying_at = null;
        $user->login_verify_count = 0;
        try {
            $user->save();
        } catch (ApiError $error) {
            logger()->error("Error saving email verification: {$error->debugText()}");
        }

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/delete-recover: a link to delete an account whose
     * password is lost. Without mail only the administrator can.
     */
    public function postDeleteRecover(Request $request): EmptyResponse
    {
        $this->limiter->check('unauthenticated', ClientIp::resolve($request, $this->config));
        $email = Body::json($request)->string('email');

        if (! $this->config->mailEnabled()) {
            throw ApiError::message('Please contact the administrator to delete your account');
        }
        $user = User::findByMail($email);
        if ($user !== null) {
            try {
                Mail::sendDeleteAccount($user->email, $user->uuid);
            } catch (ApiError $error) {
                logger()->error("Error sending delete account email: {$error->debugText()}");
            }
        }

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/delete-recover-token: the link of that mail.
     */
    public function postDeleteRecoverToken(Request $request): EmptyResponse
    {
        $body = Body::json($request);
        $userId = $body->string('userId');
        $token = $body->string('token');

        try {
            $claims = $this->jwt->decode($token, JwtIssuer::Delete);
        } catch (ApiError) {
            throw ApiError::message('Invalid claim');
        }
        $user = User::findByUuid($userId) ?? throw ApiError::message("User doesn't exist");
        if (($claims['sub'] ?? null) !== $user->uuid) {
            throw ApiError::message('Invalid claim');
        }
        $this->deleteAndLogOut($user);

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/delete and DELETE /api/accounts
     */
    public function deleteAccount(Headers $headers, Request $request): EmptyResponse
    {
        $data = PasswordOrOtpData::fromFields(Body::json($request));
        $data->validate($headers->user, true, $this->config);
        $this->deleteAndLogOut($headers->user);

        return new EmptyResponse;
    }

    /**
     * The devices are deleted together with the user, so the push devices are
     * looked for beforehand.
     *
     * @throws ApiError
     */
    private function deleteAndLogOut(User $user): void
    {
        $hasPushDevice = $this->config->bool('push_enabled') && Device::checkUserHasPushDevice($user->uuid);
        $user->deleteUser();

        $this->nt->sendLogout($user, null);
        if ($hasPushDevice) {
            Push::logoutToRelay($user, null);
        }
    }

    /**
     * POST /api/accounts/password-hint: by mail, or shown when mail is off
     * and SHOW_PASSWORD_HINT allows it. Unknown addresses look the same.
     */
    public function passwordHint(Request $request): EmptyResponse
    {
        $noHint = 'Sorry, you have no password hint...';
        $this->limiter->check('unauthenticated', ClientIp::resolve($request, $this->config));

        if (! $this->config->bool('password_hints_allowed') || (! $this->config->mailEnabled() && ! $this->config->bool('show_password_hint'))) {
            throw ApiError::message('This server is not configured to provide password hints.');
        }
        $email = Body::json($request)->string('email');

        $user = User::findByMail($email);
        if ($user === null) {
            if (! $this->config->mailEnabled()) {
                throw ApiError::message($noHint);
            }
            // Sending a mail takes time; so does pretending to.
            usleep(random_int(900, 1100) * 1000);

            return new EmptyResponse;
        }
        if ($this->config->mailEnabled()) {
            Mail::sendPasswordHint($email, $user->password_hint);

            return new EmptyResponse;
        }

        // The hint is shown, but kept out of the log.
        throw $user->password_hint === null ? ApiError::message($noHint) : ApiError::silent("Your password hint is: {$user->password_hint}");
    }

    /**
     * POST /api/accounts/verify-password: the master password policy, after the password.
     */
    public function verifyPassword(Headers $headers, Request $request): Response
    {
        $passwordHash = Body::json($request)->string('masterPasswordHash');
        $user = $headers->user;
        if (! $user->checkValidPassword($passwordHash)) {
            throw ApiError::message('Invalid password');
        }
        $this->kdfUpgrade($user, $passwordHash);

        return Json::response(MasterPasswordPolicy::forUser($user, $this->config));
    }

    /**
     * POST /api/accounts/api-key
     */
    public function postApiKey(Headers $headers, Request $request): Response
    {
        return $this->updateApiKey($headers, $request, false);
    }

    /**
     * POST /api/accounts/rotate-api-key
     */
    public function rotateApiKey(Headers $headers, Request $request): Response
    {
        return $this->updateApiKey($headers, $request, true);
    }

    /**
     * GET /api/devices/knowndevice: whether the device logged in to the
     * account before. The address comes base64url-encoded in X-Request-Email.
     */
    public function getKnownDevice(Request $request): Response
    {
        $encoded = $request->headers->get('X-Request-Email') ?? throw new HttpStatus(400, 'X-Request-Email value is required');
        // Newer clients pad the value.
        $encoded = rtrim($encoded, '=');
        $email = base64_decode(strtr($encoded, '-_', '+/'), true);
        if ($email === false || preg_match('/^[A-Za-z0-9_-]*$/D', $encoded) !== 1 || rtrim(strtr(base64_encode($email), '+/', '-_'), '=') !== $encoded) {
            throw new HttpStatus(400, 'X-Request-Email value failed to decode as base64url');
        }
        if (! mb_check_encoding($email, 'UTF-8')) {
            throw new HttpStatus(400, 'X-Request-Email value failed to decode as UTF-8');
        }
        $deviceId = $request->headers->get('X-Device-Identifier') ?? throw new HttpStatus(400, 'X-Device-Identifier value is required');

        $user = User::findByMail($email);

        return Json::response($user !== null && Device::findByUuidAndUser($deviceId, $user->uuid) !== null);
    }

    /**
     * GET /api/devices: with the login request waiting on each.
     */
    public function getAllDevices(Headers $headers): Response
    {
        $devices = [];
        foreach (Device::findByUser($headers->user->uuid) as $device) {
            $pending = AuthRequest::findByUserAndRequestedDevice($headers->user->uuid, $device->uuid);
            $devices[] = Json::sorted([
                'id' => $device->uuid,
                'name' => $device->name,
                'type' => $device->atype,
                'identifier' => $device->uuid,
                'creationDate' => Dates::format($device->created_at),
                'devicePendingAuthRequest' => $pending?->toApiForPendingDevice(),
                'isTrusted' => false,
                'encryptedPublicKey' => null,
                'encryptedUserKey' => null,
                'object' => 'device',
            ]);
        }

        return Json::response(Json::sorted(['data' => $devices, 'continuationToken' => null, 'object' => 'list']));
    }

    /**
     * GET /api/devices/identifier/{device_id}
     */
    public function getDevice(Headers $headers, string $deviceId): Response
    {
        $device = Device::findByUuidAndUser($deviceId, $headers->user->uuid) ?? throw ApiError::message('No device found');

        return Json::response($device->toApi());
    }

    /**
     * POST and PUT /api/devices/identifier/{device_id}/token: the push token
     * of the device that asks, whatever the path names.
     */
    public function putDeviceToken(Headers $headers, Request $request, string $deviceId): EmptyResponse
    {
        $token = Body::json($request)->string('pushToken');
        $device = Device::findByUuidAndUser($headers->device->uuid, $headers->user->uuid)
            ?? throw ApiError::message("Error: device {$deviceId} should be present before a token can be assigned");

        if ($device->push_token === $token) {
            return new EmptyResponse;
        }
        $device->push_token = $token;
        try {
            $device->save();
        } catch (ApiError $error) {
            throw ApiError::message("An error occurred while trying to save the device push token: {$error->displayText()}");
        }
        Push::registerDevice($device);

        return new EmptyResponse;
    }

    /**
     * PUT and POST /api/devices/identifier/{device_id}/clear-token: only with
     * push notifications on; clears the token of every device with the id.
     */
    public function putClearDeviceToken(Request $request, string $deviceId): EmptyResponse
    {
        $this->limiter->check('unauthenticated', ClientIp::resolve($request, $this->config));
        if (! $this->config->bool('push_enabled')) {
            return new EmptyResponse;
        }
        $device = Device::findByUuid($deviceId);
        if ($device !== null) {
            Device::clearPushTokenByUuid($deviceId);
            Push::unregisterDevice($device->push_uuid);
        }

        return new EmptyResponse;
    }

    /**
     * GET /api/tasks: no security tasks, without a session too.
     */
    public function getTasks(): Response
    {
        return Json::response(Json::sorted(['data' => [], 'object' => 'list']));
    }

    /**
     * POST /api/auth-requests: a device that knows the account but not the
     * key asks one of the user's devices for it.
     */
    public function postAuthRequest(Request $request): Response
    {
        $body = Body::json($request);
        $accessCode = $body->string('accessCode');
        $deviceIdentifier = $body->string('deviceIdentifier');
        $email = $body->string('email');
        $publicKey = $body->string('publicKey');
        [$deviceType, $ip] = $this->clientHeaders($request);
        $this->limiter->check('unauthenticated', $ip);

        $user = User::findByMail($email) ?? throw ApiError::message("AuthRequest doesn't exist", logMessage: 'User not found');
        $device = Device::findByUuidAndUser($deviceIdentifier, $user->uuid);
        if ($device === null || $device->atype !== $deviceType) {
            throw ApiError::message("AuthRequest doesn't exist", logMessage: 'Device verification failed');
        }

        $authRequest = AuthRequest::new($user->uuid, $deviceIdentifier, $deviceType, $ip, $accessCode, $publicKey);
        $authRequest->save();

        $this->nt->sendAuthRequest($user->uuid, $authRequest->uuid, $device);

        Event::logUser(Event::USER_REQUESTED_DEVICE_APPROVAL, $user->uuid, $deviceType, $ip);

        // A new request reads as not approved, rather than undecided.
        return Json::response([...$authRequest->toApi(), 'requestApproved' => false]);
    }

    /**
     * GET /api/auth-requests/{auth_request_id}
     */
    public function getAuthRequest(Headers $headers, string $authRequestId): Response
    {
        $authRequest = AuthRequest::findByUuidAndUser($authRequestId, $headers->user->uuid)
            ?? throw ApiError::message("AuthRequest doesn't exist", logMessage: 'Record not found or user uuid does not match');

        return Json::response($authRequest->toApi());
    }

    /**
     * PUT /api/auth-requests/{auth_request_id}: approved with the encrypted
     * key, or rejected and gone.
     */
    public function putAuthRequest(Headers $headers, Request $request, string $authRequestId): Response
    {
        $body = Body::json($request);
        $deviceIdentifier = $body->string('deviceIdentifier');
        $key = $body->string('key');
        $passwordHash = $body->optionalString('masterPasswordHash');
        $approved = $body->bool('requestApproved');

        $authRequest = AuthRequest::findByUuidAndUser($authRequestId, $headers->user->uuid)
            ?? throw ApiError::message("AuthRequest doesn't exist", logMessage: 'Record not found or user uuid does not match');
        if ($headers->device->uuid !== $deviceIdentifier) {
            throw ApiError::message("AuthRequest doesn't exist", logMessage: 'Device verification failed');
        }
        if ($authRequest->approved !== null) {
            throw ApiError::message('An authentication request with the same device already exists');
        }

        $responseDate = Dates::now();
        if ($approved) {
            $authRequest->approved = true;
            $authRequest->enc_key = $key;
            $authRequest->master_password_hash = $passwordHash;
            $authRequest->response_device_id = $deviceIdentifier;
            $authRequest->response_date = $responseDate;
            $authRequest->save();

            $this->nt->sendAnonymousAuthResponse($authRequest->user_uuid, $authRequest->uuid);
            $this->nt->sendAuthResponse($authRequest->user_uuid, $authRequest->uuid, $headers->device);

            Event::logUser(Event::ORGANIZATION_USER_APPROVED_AUTH_REQUEST, $headers->user->uuid, $headers->device->atype, $headers->ip);
        } else {
            // A rejected request is of no further use.
            $authRequest->deleteRequest();
            Event::logUser(Event::ORGANIZATION_USER_REJECTED_AUTH_REQUEST, $headers->user->uuid, $headers->device->atype, $headers->ip);
        }

        return Json::response($authRequest->toApi($responseDate));
    }

    /**
     * GET /api/auth-requests/{auth_request_id}/response: what the asking
     * device polls, with its access code, from the same IP and device type.
     */
    public function getAuthRequestResponse(Request $request, string $authRequestId): Response
    {
        // Without a code the route does not match.
        $code = Query::first($request, 'code') ?? throw new HttpStatus(404, 'No code.');
        [$deviceType, $ip] = $this->clientHeaders($request);
        $this->limiter->check('unauthenticated', $ip);

        $authRequest = AuthRequest::findByUuid($authRequestId) ?? throw ApiError::message("AuthRequest doesn't exist", logMessage: 'User not found');
        if ($authRequest->device_type !== $deviceType || $authRequest->request_ip !== $ip || ! $authRequest->checkAccessCode($code)) {
            throw ApiError::message("AuthRequest doesn't exist", logMessage: 'Invalid device, IP or code');
        }

        return Json::response($authRequest->toApi());
    }

    /**
     * GET /api/auth-requests and /api/auth-requests/pending: those still waiting.
     */
    public function getAuthRequestsPending(Headers $headers): Response
    {
        $pending = [];
        foreach (AuthRequest::findByUser($headers->user->uuid) as $authRequest) {
            if ($authRequest->approved === null) {
                $pending[] = $authRequest->toApi();
            }
        }

        return Json::response(Json::sorted(['data' => $pending, 'continuationToken' => null, 'object' => 'list']));
    }

    /**
     * update_api_key: made once, or new when rotated.
     */
    private function updateApiKey(Headers $headers, Request $request, bool $rotate): Response
    {
        $data = PasswordOrOtpData::fromFields(Body::json($request));
        $user = $headers->user;
        $data->validate($user, true, $this->config);

        if ($rotate || $user->api_key === null) {
            $user->api_key = Random::alphanumeric(30);
            $user->save();
        }

        return Json::response(Json::sorted(['apiKey' => $user->api_key, 'revisionDate' => Dates::format($user->updated_at), 'object' => 'apiKey']));
    }

    /**
     * ClientHeaders: the device type (an unknown browser when missing or no
     * number) and the client's IP.
     *
     * @return array{int, string}
     */
    private function clientHeaders(Request $request): array
    {
        return [CheckedInt::parseI32((string) $request->headers->get('Device-Type')) ?? 14, ClientIp::resolve($request, $this->config)];
    }

    /**
     * Whether the token is valid and for the subject.
     */
    private function claimsSubject(string $token, JwtIssuer $issuer, string $subject): bool
    {
        try {
            return ($this->jwt->decode($token, $issuer)['sub'] ?? null) === $subject;
        } catch (ApiError) {
            return false;
        }
    }

    /**
     * Whether some existing ids are not among the provided ones.
     *
     * @param  array<int|string>  $existing
     * @param  list<?string>  $provided
     */
    private static function missingIds(array $existing, array $provided): bool
    {
        return array_diff(array_map(static fn (int|string $id): string => (string) $id, $existing), array_filter($provided, is_string(...))) !== [];
    }
}
