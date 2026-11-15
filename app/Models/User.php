<?php

namespace App\Models;

use App\Config\Config;
use App\Http\ApiError;
use App\Http\Json;
use App\Models\Casts\Binary;
use App\Models\Casts\NaiveDateTime;
use App\Support\Dates;
use App\Support\EmailAddress;
use App\Support\EscapeDebug;
use App\Support\Random;
use DateTimeImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

/**
 * src/db/models/user.rs
 *
 * @property string $uuid
 * @property bool $enabled
 * @property DateTimeImmutable $created_at
 * @property DateTimeImmutable $updated_at
 * @property ?DateTimeImmutable $verified_at
 * @property ?DateTimeImmutable $last_verifying_at
 * @property int $login_verify_count
 * @property string $email
 * @property ?string $email_new
 * @property ?string $email_new_token
 * @property string $name
 * @property string $password_hash
 * @property string $salt
 * @property int $password_iterations
 * @property ?string $password_hint
 * @property string $akey
 * @property ?string $private_key
 * @property ?string $public_key
 * @property ?string $totp_secret
 * @property ?string $totp_recover
 * @property string $security_stamp
 * @property ?string $stamp_exception
 * @property string $equivalent_domains
 * @property string $excluded_globals
 * @property int $client_kdf_type
 * @property int $client_kdf_iter
 * @property ?int $client_kdf_memory
 * @property ?int $client_kdf_parallelism
 * @property ?string $api_key
 * @property ?string $avatar_color
 * @property ?string $external_id
 * @property ?string $key_id
 */
final class User extends Model
{
    public const int CLIENT_KDF_TYPE_DEFAULT = 0;

    public const int CLIENT_KDF_ITER_DEFAULT = 600_000;

    /**
     * Status in to_json: no password means the user was invited.
     */
    private const int STATUS_ENABLED = 0;

    private const int STATUS_INVITED = 1;

    protected $table = 'users';

    protected $primaryKey = 'uuid';

    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'created_at' => NaiveDateTime::class,
            'updated_at' => NaiveDateTime::class,
            'verified_at' => NaiveDateTime::class,
            'last_verifying_at' => NaiveDateTime::class,
            'login_verify_count' => 'integer',
            'password_hash' => Binary::class,
            'salt' => Binary::class,
            'password_iterations' => 'integer',
            'client_kdf_type' => 'integer',
            'client_kdf_iter' => 'integer',
            'client_kdf_memory' => 'integer',
            'client_kdf_parallelism' => 'integer',
        ];
    }

    /**
     * User::new: the email is stored in lower case and is the default name.
     */
    public static function new(string $email, ?string $name = null): self
    {
        $now = Dates::now();
        $email = mb_strtolower($email);

        return new self([
            'uuid' => Random::uuid(),
            'created_at' => $now,
            'updated_at' => $now,
            'email' => $email,
            'name' => $name ?? $email,
            'password_hash' => '',
            'salt' => random_bytes(64),
            'password_iterations' => app(Config::class)->int('password_iterations'),
            'password_hint' => null,
            'akey' => '',
            'private_key' => null,
            'public_key' => null,
            'totp_secret' => null,
            'totp_recover' => null,
            'security_stamp' => Random::uuid(),
            'equivalent_domains' => '[]',
            'excluded_globals' => '[]',
            'client_kdf_type' => self::CLIENT_KDF_TYPE_DEFAULT,
            'client_kdf_iter' => self::CLIENT_KDF_ITER_DEFAULT,
            'verified_at' => null,
            'last_verifying_at' => null,
            'login_verify_count' => 0,
            'email_new' => null,
            'email_new_token' => null,
            'enabled' => true,
            'stamp_exception' => null,
            'api_key' => null,
            'avatar_color' => null,
            'client_kdf_memory' => null,
            'client_kdf_parallelism' => null,
            'external_id' => null,
            'key_id' => null,
        ]);
    }

    /**
     * The client sends a hash of the master password; the server stores a PBKDF2 hash of that hash.
     */
    public function checkValidPassword(string $password): bool
    {
        return hash_equals($this->password_hash, self::hashPassword($password, $this->salt, $this->password_iterations));
    }

    public function masterPasswordSalt(): string
    {
        return mb_strtolower(trim($this->email));
    }

    public function checkValidRecoveryCode(string $recoveryCode): bool
    {
        return $this->totp_recover !== null && hash_equals(mb_strtolower($this->totp_recover), $recoveryCode);
    }

    public function checkValidApiKey(string $key): bool
    {
        return $this->api_key !== null && hash_equals($this->api_key, $key);
    }

    /**
     * Set the password hash and optionally a new user key. The security stamp
     * can be reset, and routes named in $allowNextRoute may keep using the
     * previous stamp for two minutes.
     *
     * @param  list<string>|null  $allowNextRoute
     */
    public function setPassword(string $password, ?string $newKey, bool $resetSecurityStamp, ?array $allowNextRoute): void
    {
        $this->password_hash = self::hashPassword($password, $this->salt, $this->password_iterations);

        if ($allowNextRoute !== null) {
            $this->setStampException($allowNextRoute);
        }
        if ($newKey !== null) {
            $this->akey = $newKey;
        }
        if ($resetSecurityStamp) {
            $this->resetSecurityStamp();
        }
    }

    /**
     * A new stamp signs out every session; the devices get new refresh tokens.
     */
    public function resetSecurityStamp(): void
    {
        $this->security_stamp = Random::uuid();
        Device::rotateRefreshTokensByUser($this->uuid);
    }

    /**
     * @param  list<string>  $routes  Names of the Rust handlers
     */
    public function setStampException(array $routes): void
    {
        // UserStampException serializes its fields in this order.
        $this->stamp_exception = Json::encode([
            'routes' => $routes,
            'security_stamp' => $this->security_stamp,
            'expire' => Dates::now()->getTimestamp() + 120,
        ]);
    }

    public function resetStampException(): void
    {
        $this->stamp_exception = null;
    }

    /**
     * The name, or the email when the name is empty.
     */
    public function displayName(): string
    {
        return $this->name === '' ? $this->email : $this->name;
    }

    /**
     * Without mail, users count as verified.
     */
    public function verified(): bool
    {
        return ! app(Config::class)->mailEnabled() || $this->verified_at !== null;
    }

    /**
     * The `accountKeys` object (upstream's PrivateKeysResponseModel), null without a key pair.
     *
     * @return array<string, mixed>|null
     */
    public function accountKeysJson(): ?array
    {
        if ($this->private_key === null) {
            return null;
        }

        return Json::sorted([
            'publicKeyEncryptionKeyPair' => [
                'wrappedPrivateKey' => $this->private_key,
                'publicKey' => $this->public_key,
                'signedPublicKey' => null,
                'object' => 'publicKeyEncryptionKeyPair',
            ],
            'securityState' => null,
            'signatureKeyPair' => null,
            'object' => 'privateKeys',
        ]);
    }

    /**
     * User::to_json: the profile as the API shows it.
     *
     * @return array<string, mixed>
     */
    public function toApi(): array
    {
        $organizations = Membership::findConfirmedByUser($this->uuid)->map(static fn (Membership $member): array => $member->toApiProfile())->all();
        $organizationsNew = Membership::findAcceptedAndConfirmedByUser($this->uuid)->map(static fn (Membership $member): array => $member->toApiProfile())->all();

        return Json::sorted([
            '_status' => $this->status(),
            'accountKeys' => $this->accountKeysJson(),
            'id' => $this->uuid,
            'name' => $this->name,
            'email' => $this->email,
            'emailVerified' => $this->verified(),
            'premium' => true,
            'premiumFromOrganization' => false,
            'culture' => 'en-US',
            'twoFactorEnabled' => TwoFactor::findByUser($this->uuid)->isNotEmpty(),
            'key' => $this->akey,
            'privateKey' => $this->private_key,
            'securityStamp' => $this->security_stamp,
            'organizations' => array_values($organizations),
            'organizationsNew' => array_values($organizationsNew),
            'providers' => [],
            'providerOrganizations' => [],
            'forcePasswordReset' => false,
            'avatarColor' => $this->avatar_color,
            'usesKeyConnector' => false,
            'creationDate' => Dates::format($this->created_at),
            'object' => 'profile',
        ]);
    }

    public function status(): int
    {
        return $this->password_hash === '' ? self::STATUS_INVITED : self::STATUS_ENABLED;
    }

    /**
     * Insert or update the user; the email must be valid.
     *
     * @param  array<string, mixed>  $options
     *
     * @throws ApiError
     */
    public function save(array $options = []): bool
    {
        if (! EmailAddress::isValid($this->email)) {
            throw ApiError::message('User email '.EscapeDebug::of($this->email).' is not a valid email address');
        }

        $this->updated_at = Dates::now();
        $this->upsertRow(['uuid'], 'Error saving user');

        return true;
    }

    /**
     * Touch the revision date, which tells clients to sync.
     *
     * @throws ApiError
     */
    public function updateRevision(): void
    {
        $this->updated_at = Dates::now();
        self::updateRevisionOf($this->uuid, $this->updated_at);
    }

    /**
     * update_uuid_revision: failures are only logged.
     */
    /**
     * User::delete: with everything of the user. The last owner of an
     * organization cannot go.
     *
     * @throws ApiError
     */
    public function deleteUser(): void
    {
        foreach (Membership::findConfirmedByUser($this->uuid) as $member) {
            if ($member->atype === Membership::TYPE_OWNER && Membership::countConfirmedByOrgAndType($member->org_uuid, Membership::TYPE_OWNER) <= 1) {
                throw ApiError::message("Can't delete last owner");
            }
        }

        Send::deleteAllByUser($this->uuid);
        EmergencyAccess::deleteAllByUser($this->uuid);
        EmergencyAccess::deleteAllByGranteeEmail($this->email);
        Membership::deleteAllByUser($this->uuid);
        Cipher::deleteAllByUser($this->uuid);
        Favorite::deleteAllByUser($this->uuid);
        Folder::deleteAllByUser($this->uuid);
        self::deleteRowsOf('auth_requests', $this->uuid, 'Error deleting auth requests for user');
        Device::deleteAllByUser($this->uuid);
        TwoFactor::deleteAllByUser($this->uuid);
        self::deleteRowsOf('twofactor_incomplete', $this->uuid, 'Error in twofactor_incomplete::delete_all_by_user()');
        Invitation::take($this->email);

        try {
            self::query()->where('uuid', $this->uuid)->delete();
        } catch (QueryException) {
            throw ApiError::message('Error deleting user');
        }
    }

    /**
     * @throws ApiError
     */
    private static function deleteRowsOf(string $table, string $userUuid, string $error): void
    {
        try {
            DB::table($table)->where('user_uuid', $userUuid)->delete();
        } catch (QueryException) {
            throw ApiError::message($error);
        }
    }

    public static function updateUuidRevision(string $uuid): void
    {
        try {
            self::updateRevisionOf($uuid, Dates::now());
        } catch (ApiError $error) {
            logger()->warning("Failed to update revision for {$uuid}: {$error->getMessage()}");
        }
    }

    /**
     * @throws ApiError
     */
    public static function updateAllRevisions(): void
    {
        self::retry(
            static fn () => self::query()->update(['updated_at' => NaiveDateTime::format(Dates::now())]),
            'Error updating revision date for all users',
        );
    }

    /**
     * User::get_all: every user, with the identifier of its SSO link.
     *
     * @return list<array{self, ?string}>
     */
    public static function getAll(): array
    {
        $identifiers = SsoUser::identifiers();

        return array_values(self::query()->get()->map(static fn (self $user): array => [$user, $identifiers[$user->uuid] ?? null])->all());
    }

    public static function findByMail(string $mail): ?self
    {
        return self::query()->where('email', mb_strtolower($mail))->first();
    }

    public static function findByUuid(string $uuid): ?self
    {
        return self::query()->where('uuid', $uuid)->first();
    }

    public function lastActive(): ?DateTimeImmutable
    {
        return Device::findLatestActiveByUser($this->uuid)?->updated_at;
    }

    /**
     * crypto::hash_password: PBKDF2-HMAC-SHA256 with 32 bytes of output.
     * OpenSSL's implementation gives the same bytes as hash_pbkdf2() in a
     * fraction of the time, which matters at 600,000 iterations per login.
     */
    public static function hashPassword(string $password, string $salt, int $iterations): string
    {
        $hash = openssl_pbkdf2($password, $salt, 32, max(1, $iterations), 'sha256');

        return $hash === false ? hash_pbkdf2('sha256', $password, $salt, max(1, $iterations), 32, true) : $hash;
    }

    /**
     * @throws ApiError
     */
    private static function updateRevisionOf(string $uuid, DateTimeImmutable $date): void
    {
        self::retry(
            static fn () => self::query()->where('uuid', $uuid)->update(['updated_at' => NaiveDateTime::format($date)]),
            'Error updating user revision',
        );
    }

    protected function binaryColumns(): array
    {
        return ['password_hash', 'salt'];
    }
}
