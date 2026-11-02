<?php

namespace App\Models;

use App\Config\Config;
use App\Http\ApiError;
use App\Http\Data\NumberOrString;
use App\Http\Json;
use App\Models\Casts\Binary;
use App\Models\Casts\NaiveDateTime;
use App\Support\CheckedInt;
use App\Support\Dates;
use App\Support\JsonValue;
use App\Support\Random;
use App\Support\Uuid;
use DateTimeImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use stdClass;

/**
 * A Send (src/db/models/send.rs). The file of a file Send lies at
 * `<SENDS_FOLDER>/<uuid>/<file id>`.
 *
 * @property string $uuid
 * @property ?string $user_uuid
 * @property ?string $organization_uuid
 * @property string $name
 * @property ?string $notes
 * @property int $atype
 * @property string $data
 * @property string $akey
 * @property ?string $password_hash
 * @property ?string $password_salt
 * @property ?int $password_iter
 * @property ?int $max_access_count
 * @property int $access_count
 * @property DateTimeImmutable $creation_date
 * @property DateTimeImmutable $revision_date
 * @property ?DateTimeImmutable $expiration_date
 * @property DateTimeImmutable $deletion_date
 * @property bool $disabled
 * @property ?bool $hide_email
 */
final class Send extends Model
{
    public const int TYPE_TEXT = 0;

    public const int TYPE_FILE = 1;

    /**
     * SendAuthType: Vaultwarden knows no email authentication (0) yet.
     */
    private const int AUTH_PASSWORD = 1;

    private const int AUTH_NONE = 2;

    /**
     * Send::set_password: PBKDF2 rounds over the client's password hash.
     */
    private const int PASSWORD_ITERATIONS = 100_000;

    protected $table = 'sends';

    protected $primaryKey = 'uuid';

    protected function casts(): array
    {
        return [
            'atype' => 'integer',
            'password_hash' => Binary::class,
            'password_salt' => Binary::class,
            'password_iter' => 'integer',
            'max_access_count' => 'integer',
            'access_count' => 'integer',
            'creation_date' => NaiveDateTime::class,
            'revision_date' => NaiveDateTime::class,
            'expiration_date' => NaiveDateTime::class,
            'deletion_date' => NaiveDateTime::class,
            'disabled' => 'boolean',
            'hide_email' => 'boolean',
        ];
    }

    protected function binaryColumns(): array
    {
        return ['password_hash', 'password_salt'];
    }

    public static function new(int $type, string $name, string $data, string $key, DateTimeImmutable $deletionDate): self
    {
        $now = Dates::now();
        $send = new self;
        $send->setRawAttributes([
            'uuid' => Random::uuid(),
            'user_uuid' => null,
            'organization_uuid' => null,
            'name' => $name,
            'notes' => null,
            'atype' => $type,
            'data' => $data,
            'akey' => $key,
            'password_hash' => null,
            'password_salt' => null,
            'password_iter' => null,
            'max_access_count' => null,
            'access_count' => 0,
            'creation_date' => null,
            'revision_date' => null,
            'expiration_date' => null,
            'deletion_date' => null,
            'disabled' => false,
            'hide_email' => null,
        ]);
        $send->creation_date = $now;
        $send->revision_date = $now;
        $send->deletion_date = $deletionDate;

        return $send;
    }

    /**
     * crypto::generate_send_file_id: 256 random bits, as file ids are global.
     */
    public static function generateFileId(): string
    {
        return Random::hex(32);
    }

    public static function filePath(string $sendUuid, string $fileId): string
    {
        return app(Config::class)->path('sends_folder')."/{$sendUuid}/{$fileId}";
    }

    /**
     * @param  array<string, mixed>  $options
     *
     * @throws ApiError
     */
    public function save(array $options = []): bool
    {
        $this->updateUsersRevision();
        $this->revision_date = Dates::now();
        $this->upsertRow(['uuid'], 'Error saving send');

        return true;
    }

    /**
     * The client sends a hash of the password, which is hashed again; null removes it.
     */
    public function setPassword(?string $password): void
    {
        if ($password === null) {
            $this->password_iter = null;
            $this->password_salt = null;
            $this->password_hash = null;

            return;
        }

        $salt = random_bytes(64);
        $this->password_iter = self::PASSWORD_ITERATIONS;
        $this->password_salt = $salt;
        $this->password_hash = User::hashPassword($password, $salt, self::PASSWORD_ITERATIONS);
    }

    public function checkPassword(string $password): bool
    {
        if ($this->password_hash === null || $this->password_salt === null || $this->password_iter === null) {
            return false;
        }

        return hash_equals($this->password_hash, User::hashPassword($password, $this->password_salt, $this->password_iter));
    }

    /**
     * Within its validity: enabled, not expired and not due for deletion.
     * The access count and the password are checked elsewhere.
     */
    public function isAccessible(): bool
    {
        $now = Dates::now();

        return ! $this->disabled
            && ($this->expiration_date === null || $now < $this->expiration_date)
            && $now < $this->deletion_date;
    }

    /**
     * Count an access unless the limit is reached, in one statement, so that
     * concurrent accesses cannot exceed it.
     *
     * @return bool Whether the access was counted
     */
    public function registerAccess(): bool
    {
        $this->updateUsersRevision();

        $revision = Dates::now();
        $updated = self::query()
            ->where('uuid', $this->uuid)
            ->where(static fn (Builder $query) => $query->whereNull('max_access_count')->orWhereColumn('access_count', '<', 'max_access_count'))
            ->update(['access_count' => DB::raw('access_count + 1'), 'revision_date' => NaiveDateTime::format($revision)]);

        if ($updated === 0) {
            return false;
        }

        $this->access_count++;
        $this->revision_date = $revision;
        $this->syncOriginal();

        return true;
    }

    /**
     * Deletes the row and, for a file Send, its folder.
     *
     * @throws ApiError
     */
    public function deleteSend(): void
    {
        $this->updateUsersRevision();

        if ($this->atype === self::TYPE_FILE) {
            File::deleteDirectory(app(Config::class)->path('sends_folder')."/{$this->uuid}");
        }

        try {
            self::query()->where('uuid', $this->uuid)->delete();
        } catch (QueryException) {
            throw ApiError::message('Error deleting send');
        }
    }

    /**
     * Sends of organizations are not implemented upstream either.
     *
     * @return list<string> The users whose clients must sync
     */
    public function updateUsersRevision(): array
    {
        if ($this->user_uuid === null) {
            return [];
        }
        User::updateUuidRevision($this->user_uuid);

        return [$this->user_uuid];
    }

    /**
     * @return array<string, mixed>
     */
    public function toApi(): array
    {
        $data = $this->dataJson();

        return Json::sorted([
            'id' => $this->uuid,
            'accessId' => $this->accessId(),
            'type' => $this->atype,
            'name' => $this->name,
            'notes' => $this->notes,
            'text' => $this->atype === self::TYPE_TEXT ? $data : null,
            'file' => $this->atype === self::TYPE_FILE ? $data : null,
            'key' => $this->akey,
            'maxAccessCount' => $this->max_access_count,
            'accessCount' => $this->access_count,
            'password' => $this->password_hash === null ? null : rtrim(strtr(base64_encode($this->password_hash), '+/', '-_'), '='),
            'authType' => $this->password_hash === null ? self::AUTH_NONE : self::AUTH_PASSWORD,
            'disabled' => $this->disabled,
            'hideEmail' => $this->hide_email ?? false,
            'revisionDate' => Dates::format($this->revision_date),
            'expirationDate' => $this->expiration_date === null ? null : Dates::format($this->expiration_date),
            'deletionDate' => Dates::format($this->deletion_date),
            'object' => 'send',
        ]);
    }

    /**
     * Send::to_json_access: what the recipient of the link sees.
     *
     * @return array<string, mixed>
     */
    public function toApiAccess(): array
    {
        return Json::sorted([
            'id' => $this->accessId(),
            'type' => $this->atype,
            'name' => $this->name,
            'text' => $this->atype === self::TYPE_TEXT ? $this->dataJson() : null,
            'file' => $this->atype === self::TYPE_FILE ? $this->dataJson() : null,
            'expirationDate' => $this->expiration_date === null ? null : Dates::format($this->expiration_date),
            'creatorIdentifier' => $this->creatorIdentifier(),
            'object' => 'send-access',
        ]);
    }

    /**
     * The creator's email, unless the Send hides it.
     */
    public function creatorIdentifier(): ?string
    {
        if ($this->hide_email === true || $this->user_uuid === null) {
            return null;
        }

        return User::findByUuid($this->user_uuid)?->email;
    }

    /**
     * The UUID's 16 bytes in unpadded base64url; the nil UUID when it is none.
     */
    public function accessId(): string
    {
        $hex = Uuid::isValid($this->uuid)
            ? (string) preg_replace('/[^0-9a-fA-F]/', '', (string) preg_replace('/^urn:uuid:/', '', $this->uuid))
            : str_repeat('0', 32);

        return rtrim(strtr(base64_encode((string) hex2bin($hex)), '+/', '-_'), '=');
    }

    /**
     * SendTokens::as_send_id: the UUID behind an access id (16 bytes in
     * canonical unpadded base64url), hyphenated in lower case.
     */
    public static function uuidFromAccessId(string $accessId): ?string
    {
        if (! preg_match('/^[A-Za-z0-9_-]*$/D', $accessId) || strlen($accessId) % 4 === 1) {
            return null;
        }
        $bytes = base64_decode(strtr($accessId, '-_', '+/'), true);
        // data_encoding rejects non-zero trailing bits, so only one spelling decodes.
        if ($bytes === false || strlen($bytes) !== 16 || rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=') !== $accessId) {
            return null;
        }
        $hex = bin2hex($bytes);

        return substr($hex, 0, 8).'-'.substr($hex, 8, 4).'-'.substr($hex, 12, 4).'-'.substr($hex, 16, 4).'-'.substr($hex, 20);
    }

    public static function findByUuid(string $uuid): ?self
    {
        return self::query()->where('uuid', $uuid)->first();
    }

    public static function findByUuidAndUser(string $uuid, string $userUuid): ?self
    {
        return self::query()->where('uuid', $uuid)->where('user_uuid', $userUuid)->first();
    }

    /**
     * The bytes of the user's file Sends, as their data states them; null
     * when the sum overflows.
     */
    public static function sizeByUser(string $userUuid): ?int
    {
        $total = 0;
        foreach (self::findByUser($userUuid) as $send) {
            if ($send->atype !== self::TYPE_FILE) {
                continue;
            }
            // FileData { size: NumberOrString }, which as a derived struct also reads
            // from a sequence; Sends without it do not count.
            [$ok, $data] = JsonValue::decode($send->data);
            $size = match (true) {
                ! $ok => null,
                $data instanceof stdClass => $data->size ?? null,
                is_array($data) && array_is_list($data) && count($data) === 1 => $data[0],
                default => null,
            };
            if (! is_int($size) && ! is_string($size)) {
                continue;
            }
            try {
                $size = NumberOrString::intoI64($size);
            } catch (ApiError) {
                continue;
            }
            $total = CheckedInt::add($total, $size);
            if ($total === null) {
                return null;
            }
        }

        return $total;
    }

    /**
     * Deletes the Sends past their deletion date; failures are ignored like upstream.
     */
    public static function purge(): void
    {
        foreach (self::findByPastDeletionDate() as $send) {
            try {
                $send->deleteSend();
            } catch (ApiError) {
                // Tried again on the next run.
            }
        }
    }

    /**
     * @throws ApiError
     */
    public static function deleteAllByUser(string $userUuid): void
    {
        foreach (self::findByUser($userUuid) as $send) {
            $send->deleteSend();
        }
    }

    /**
     * @return Collection<int, self>
     */
    public static function findByUser(string $userUuid): Collection
    {
        return self::query()->where('user_uuid', $userUuid)->get();
    }

    /**
     * @return Collection<int, self>
     */
    public static function findByPastDeletionDate(): Collection
    {
        return self::query()->where('deletion_date', '<', NaiveDateTime::format(Dates::now()))->get();
    }

    /**
     * The data as LowerCase<Value> reads it (objects only, else null), with
     * the size as a string, which mobile clients expect.
     */
    private function dataJson(): mixed
    {
        [$ok, $decoded] = JsonValue::decode($this->data);
        $data = $ok && $decoded instanceof stdClass ? JsonValue::lowercaseKeys($decoded) : null;

        if (is_array($data) && is_int($data['size'] ?? null)) {
            $data['size'] = (string) $data['size'];
        }

        return $data;
    }
}
