<?php

namespace App\Models;

use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Json;
use App\Models\Casts\NaiveDateTime;
use App\Support\Dates;
use App\Support\Random;
use DateTimeImmutable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\QueryException;

/**
 * src/db/models/device.rs; the key is (uuid, user_uuid).
 *
 * @property string $uuid
 * @property DateTimeImmutable $created_at
 * @property DateTimeImmutable $updated_at
 * @property string $user_uuid
 * @property string $name
 * @property int $atype
 * @property ?string $push_token
 * @property string $refresh_token
 * @property ?string $twofactor_remember
 * @property ?string $push_uuid
 */
final class Device extends Model
{
    protected $table = 'devices';

    protected $primaryKey = 'uuid';

    protected function casts(): array
    {
        return [
            'created_at' => NaiveDateTime::class,
            'updated_at' => NaiveDateTime::class,
            'atype' => 'integer',
        ];
    }

    public static function new(string $uuid, string $userUuid, string $name, int $atype): self
    {
        $now = Dates::now();

        return new self([
            'uuid' => $uuid,
            'created_at' => $now,
            'updated_at' => $now,
            'user_uuid' => $userUuid,
            'name' => $name,
            'atype' => $atype,
            'push_token' => null,
            'refresh_token' => self::generateRefreshToken(),
            'twofactor_remember' => null,
            'push_uuid' => Random::uuid(),
        ]);
    }

    /**
     * 64 random bytes in URL-safe base64 with padding.
     */
    public static function generateRefreshToken(): string
    {
        return Random::base64Url(64);
    }

    /**
     * Device::to_json, the device as the API shows it.
     *
     * @return array<string, mixed>
     */
    public function toApi(): array
    {
        return Json::sorted([
            'id' => $this->uuid,
            'name' => $this->name,
            'type' => $this->atype,
            'identifier' => $this->uuid,
            'creationDate' => Dates::format($this->created_at),
            'isTrusted' => false,
            'object' => 'device',
        ]);
    }

    /**
     * A new "remember this device" token for two-factor login, valid for
     * TWO_FACTOR_REMEMBER_DAYS.
     */
    public function refreshTwofactorRemember(): string
    {
        $jwt = app(Jwt::class);
        $now = Dates::now()->getTimestamp();

        // TwoFactorRememberClaims
        $token = $jwt->encode([
            'nbf' => $now,
            'exp' => $now + app(Config::class)->int('two_factor_remember_days') * 86_400,
            'iss' => $jwt->issuer(JwtIssuer::TwoFactorRemember),
            'sub' => $this->uuid,
            'user_uuid' => $this->user_uuid,
        ]);
        $this->twofactor_remember = $token;

        return $token;
    }

    public function deleteTwofactorRemember(): void
    {
        $this->twofactor_remember = null;
    }

    /**
     * Devices are only saved after a successful login, so equal timestamps mean a first login.
     */
    public function isNew(): bool
    {
        return $this->created_at == $this->updated_at;
    }

    public function type(): DeviceType
    {
        return DeviceType::fromInt($this->atype);
    }

    public function isPushDevice(): bool
    {
        return in_array($this->type(), [DeviceType::Android, DeviceType::Ios], true);
    }

    public function isCli(): bool
    {
        return in_array($this->type(), [DeviceType::WindowsCLI, DeviceType::MacOsCLI, DeviceType::LinuxCLI], true);
    }

    public function isMobile(): bool
    {
        return in_array($this->type(), [DeviceType::Android, DeviceType::Ios], true);
    }

    /**
     * Insert or update the device, with up to ten attempts.
     *
     * @param  array{update_time?: bool}  $options  update_time (default true) touches updated_at
     *
     * @throws ApiError
     */
    public function save(array $options = []): bool
    {
        if ($options['update_time'] ?? true) {
            $this->updated_at = Dates::now();
        }

        $this->upsertRow(['uuid', 'user_uuid'], 'Error saving device', tries: 10);

        return true;
    }

    /**
     * @throws ApiError
     */
    public static function deleteAllByUser(string $userUuid): void
    {
        self::run(static fn () => self::query()->where('user_uuid', $userUuid)->delete(), 'Error removing devices for user');
    }

    public static function findByUuidAndUser(string $uuid, string $userUuid): ?self
    {
        return self::query()->where('uuid', $uuid)->where('user_uuid', $userUuid)->first();
    }

    /**
     * @return Collection<int, self>
     */
    public static function findByUser(string $userUuid): Collection
    {
        return self::query()->where('user_uuid', $userUuid)->get();
    }

    public static function findByUuid(string $uuid): ?self
    {
        return self::query()->where('uuid', $uuid)->first();
    }

    /**
     * @throws ApiError
     */
    public static function clearPushTokenByUuid(string $uuid): void
    {
        self::run(static fn () => self::query()->where('uuid', $uuid)->update(['push_token' => null]), 'Error removing push token');
    }

    public static function findByRefreshToken(string $refreshToken): ?self
    {
        return self::query()->where('refresh_token', $refreshToken)->first();
    }

    public static function findLatestActiveByUser(string $userUuid): ?self
    {
        return self::query()->where('user_uuid', $userUuid)->orderByDesc('updated_at')->first();
    }

    /**
     * @return Collection<int, self>
     */
    public static function findPushDevicesByUser(string $userUuid): Collection
    {
        return self::query()->where('user_uuid', $userUuid)->whereNotNull('push_token')->get();
    }

    public static function checkUserHasPushDevice(string $userUuid): bool
    {
        return self::query()->where('user_uuid', $userUuid)->whereNotNull('push_token')->exists();
    }

    /**
     * Each device needs its own token, so they are saved one by one, without touching updated_at.
     *
     * @throws ApiError
     */
    public static function rotateRefreshTokensByUser(string $userUuid): void
    {
        foreach (self::findByUser($userUuid) as $device) {
            $device->refresh_token = self::generateRefreshToken();
            $device->twofactor_remember = null;
            $device->save(['update_time' => false]);
        }
    }

    /**
     * @throws ApiError
     */
    public static function clearTwofactorRememberByUser(string $userUuid): void
    {
        self::run(
            static fn () => self::query()->where('user_uuid', $userUuid)->update(['twofactor_remember' => null]),
            'Error removing two factor remember tokens',
        );
    }

    /**
     * @throws ApiError
     */
    private static function run(callable $query, string $errorMessage): void
    {
        try {
            $query();
        } catch (QueryException) {
            throw ApiError::message($errorMessage);
        }
    }
}
