<?php

namespace App\Models;

use App\Config\Config;
use App\Http\ApiError;
use App\Http\Json;
use App\Models\Casts\NaiveDateTime;
use App\Support\Dates;
use App\Support\Random;
use DateTimeImmutable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Query\JoinClause;
use Illuminate\Database\QueryException;
use Throwable;

/**
 * An entry of the organization event log (src/db/models/event.rs), written
 * by api::core::events::log_event and log_user_event with ORG_EVENTS_ENABLED.
 *
 * @property string $uuid
 * @property int $event_type
 * @property ?string $user_uuid
 * @property ?string $org_uuid
 * @property ?string $cipher_uuid
 * @property ?string $collection_uuid
 * @property ?string $group_uuid
 * @property ?string $org_user_uuid
 * @property ?string $act_user_uuid
 * @property ?int $device_type
 * @property ?string $ip_address
 * @property DateTimeImmutable $event_date
 * @property ?string $policy_uuid
 * @property ?string $provider_uuid
 * @property ?string $provider_user_uuid
 * @property ?string $provider_org_uuid
 */
final class Event extends Model
{
    public const int USER_LOGGED_IN = 1000;

    public const int USER_CHANGED_PASSWORD = 1001;

    public const int USER_UPDATED_2FA = 1002;

    public const int USER_DISABLED_2FA = 1003;

    public const int USER_RECOVERED_2FA = 1004;

    public const int USER_FAILED_LOG_IN = 1005;

    public const int USER_FAILED_LOG_IN_2FA = 1006;

    public const int USER_CLIENT_EXPORTED_VAULT = 1007;

    public const int USER_REQUESTED_DEVICE_APPROVAL = 1010;

    public const int CIPHER_CREATED = 1100;

    public const int CIPHER_UPDATED = 1101;

    public const int CIPHER_DELETED = 1102;

    public const int CIPHER_ATTACHMENT_CREATED = 1103;

    public const int CIPHER_ATTACHMENT_DELETED = 1104;

    public const int CIPHER_SHARED = 1105;

    public const int CIPHER_UPDATED_COLLECTIONS = 1106;

    public const int CIPHER_SOFT_DELETED = 1115;

    public const int CIPHER_RESTORED = 1116;

    public const int CIPHER_CLIENT_HTTP_AUTH_RELEASED = 1133;

    public const int COLLECTION_CREATED = 1300;

    public const int COLLECTION_UPDATED = 1301;

    public const int COLLECTION_DELETED = 1302;

    public const int GROUP_CREATED = 1400;

    public const int GROUP_UPDATED = 1401;

    public const int GROUP_DELETED = 1402;

    public const int ORGANIZATION_USER_INVITED = 1500;

    public const int ORGANIZATION_USER_CONFIRMED = 1501;

    public const int ORGANIZATION_USER_UPDATED = 1502;

    public const int ORGANIZATION_USER_REMOVED = 1503;

    public const int ORGANIZATION_USER_UPDATED_GROUPS = 1504;

    public const int ORGANIZATION_USER_UNLINKED_SSO = 1505;

    public const int ORGANIZATION_USER_RESET_PASSWORD_ENROLL = 1506;

    public const int ORGANIZATION_USER_RESET_PASSWORD_WITHDRAW = 1507;

    public const int ORGANIZATION_USER_ADMIN_RESET_PASSWORD = 1508;

    public const int ORGANIZATION_USER_REVOKED = 1511;

    public const int ORGANIZATION_USER_RESTORED = 1512;

    public const int ORGANIZATION_USER_APPROVED_AUTH_REQUEST = 1513;

    public const int ORGANIZATION_USER_REJECTED_AUTH_REQUEST = 1514;

    // Both the user and the membership were deleted.
    public const int ORGANIZATION_USER_DELETED = 1515;

    public const int ORGANIZATION_USER_LEFT = 1516;

    public const int ORGANIZATION_USER_ADMIN_RESET_TWO_FACTOR = 1519;

    public const int ORGANIZATION_USER_REVOKED_TWO_FACTOR_NON_COMPLIANCE = 1520;

    public const int ORGANIZATION_USER_REVOKED_SINGLE_ORGANIZATION_NON_COMPLIANCE = 1521;

    public const int ORGANIZATION_USER_NOTIFICATION_BANNER_ACTION_CLICKED = 1522;

    public const int ORGANIZATION_UPDATED = 1600;

    public const int ORGANIZATION_PURGED_VAULT = 1601;

    public const int ORGANIZATION_CLIENT_EXPORTED_VAULT = 1602;

    public const int POLICY_UPDATED = 1700;

    /**
     * The events of one page; a full page has a continuation token.
     */
    public const int PAGE_SIZE = 30;

    protected $table = 'event';

    protected $primaryKey = 'uuid';

    protected function casts(): array
    {
        return [
            'event_type' => 'integer',
            'device_type' => 'integer',
            'event_date' => NaiveDateTime::class,
        ];
    }

    public static function new(int $type, ?DateTimeImmutable $date = null): self
    {
        $event = new self;
        $event->setRawAttributes(array_fill_keys(['uuid', 'event_type', 'user_uuid', 'org_uuid', 'cipher_uuid', 'collection_uuid', 'group_uuid', 'org_user_uuid',
            'act_user_uuid', 'device_type', 'ip_address', 'event_date', 'policy_uuid', 'provider_uuid', 'provider_user_uuid', 'provider_org_uuid'], null));
        $event->uuid = Random::uuid();
        $event->event_type = $type;
        $event->event_date = $date ?? Dates::now();

        return $event;
    }

    /**
     * api::core::events::log_event: an event of an organization, about what
     * the source id names, by the type's range.
     */
    public static function log(int $type, string $sourceUuid, string $orgUuid, string $actUserUuid, int $deviceType, string $ip): void
    {
        if (app(Config::class)->bool('org_events_enabled')) {
            self::logImpl($type, $sourceUuid, $orgUuid, $actUserUuid, $deviceType, null, $ip);
        }
    }

    public static function logImpl(int $type, string $sourceUuid, string $orgUuid, string $actUserUuid, int $deviceType, ?DateTimeImmutable $date, string $ip): void
    {
        $event = self::new($type, $date);
        match (true) {
            // 1000-1099 are user events, logged with logUser.
            $type >= 1100 && $type <= 1199 => $event->cipher_uuid = $sourceUuid,
            $type >= 1300 && $type <= 1399 => $event->collection_uuid = $sourceUuid,
            $type >= 1400 && $type <= 1499 => $event->group_uuid = $sourceUuid,
            $type >= 1500 && $type <= 1599 => $event->org_user_uuid = $sourceUuid,
            // 1600-1699 are about the organization itself.
            $type >= 1700 && $type <= 1799 => $event->policy_uuid = $sourceUuid,
            default => null,
        };
        $event->org_uuid = $orgUuid;
        $event->act_user_uuid = $actUserUuid;
        $event->device_type = $deviceType;
        $event->ip_address = $ip;

        try {
            $event->save();
        } catch (ApiError) {
            // Logging never fails the request.
        }
    }

    /**
     * api::core::events::log_user_event: one event without organization and
     * one for each organization the user is a confirmed member of.
     */
    public static function logUser(int $type, string $userUuid, int $deviceType, string $ip): void
    {
        if (app(Config::class)->bool('org_events_enabled')) {
            self::logUserImpl($type, $userUuid, $deviceType, null, $ip);
        }
    }

    public static function logUserImpl(int $type, string $userUuid, int $deviceType, ?DateTimeImmutable $date, string $ip): void
    {
        $events = [];
        foreach ([null, ...Membership::findConfirmedByUser($userUuid)] as $membership) {
            $event = self::new($type, $date);
            $event->user_uuid = $userUuid;
            $event->org_uuid = $membership?->org_uuid;
            $event->org_user_uuid = $membership?->uuid;
            $event->act_user_uuid = $userUuid;
            $event->device_type = $deviceType;
            $event->ip_address = $ip;
            $events[] = $event;
        }

        foreach ($events as $event) {
            try {
                self::query()->insertOrIgnore($event->getAttributes());
            } catch (Throwable) {
                // Ignored like upstream's unwrap_or_default.
            }
        }
    }

    /**
     * @param  array<string, mixed>  $options
     *
     * @throws ApiError
     */
    public function save(array $options = []): bool
    {
        $this->upsertRow(['uuid'], 'Error saving event');

        return true;
    }

    /**
     * Event::to_json
     *
     * @return array<string, mixed>
     */
    public function toApi(): array
    {
        return Json::sorted([
            'type' => $this->event_type,
            'userId' => $this->user_uuid,
            'organizationId' => $this->org_uuid,
            'cipherId' => $this->cipher_uuid,
            'collectionId' => $this->collection_uuid,
            'groupId' => $this->group_uuid,
            'organizationUserId' => $this->org_user_uuid,
            'actingUserId' => $this->act_user_uuid,
            'date' => Dates::format($this->event_date),
            'deviceType' => $this->device_type,
            'ipAddress' => $this->ip_address,
            'policyId' => $this->policy_uuid,
            'providerId' => $this->provider_uuid,
            'providerUserId' => $this->provider_user_uuid,
            'providerOrganizationId' => $this->provider_org_uuid,
        ]);
    }

    /**
     * The newest page of the organization's events between the dates.
     *
     * @return Collection<int, self>
     */
    public static function findByOrganizationUuid(string $orgUuid, DateTimeImmutable $start, DateTimeImmutable $end): Collection
    {
        return self::query()
            ->where('org_uuid', $orgUuid)
            ->whereBetween('event_date', [NaiveDateTime::format($start), NaiveDateTime::format($end)])
            ->orderByDesc('event_date')
            ->limit(self::PAGE_SIZE)
            ->get();
    }

    /**
     * The organization's events about the member, of them or by them.
     *
     * @return Collection<int, self>
     */
    public static function findByOrgAndMember(string $orgUuid, string $memberUuid, DateTimeImmutable $start, DateTimeImmutable $end): Collection
    {
        return self::query()
            ->join('users_organizations', function (JoinClause $join) use ($memberUuid, $orgUuid): void {
                $join->where('users_organizations.uuid', '=', $memberUuid)->where('users_organizations.org_uuid', '=', $orgUuid);
            })
            ->where('event.org_uuid', $orgUuid)
            ->whereBetween('event.event_date', [NaiveDateTime::format($start), NaiveDateTime::format($end)])
            ->where(static fn ($query) => $query->where('event.org_user_uuid', $memberUuid)
                ->orWhereColumn('event.user_uuid', 'users_organizations.user_uuid')
                ->orWhereColumn('event.act_user_uuid', 'users_organizations.user_uuid'))
            ->select('event.*')
            ->orderByDesc('event.event_date')
            ->limit(self::PAGE_SIZE)
            ->get();
    }

    /**
     * @return Collection<int, self>
     */
    public static function findByCipherUuid(string $cipherUuid, DateTimeImmutable $start, DateTimeImmutable $end): Collection
    {
        return self::query()
            ->where('cipher_uuid', $cipherUuid)
            ->whereBetween('event_date', [NaiveDateTime::format($start), NaiveDateTime::format($end)])
            ->orderByDesc('event_date')
            ->limit(self::PAGE_SIZE)
            ->get();
    }

    public static function countByOrg(string $orgUuid): int
    {
        return self::query()->where('org_uuid', $orgUuid)->count();
    }

    /**
     * Event::clean_events: removes the events older than EVENTS_DAYS_RETAIN days.
     *
     * @throws ApiError
     */
    public static function cleanEvents(): void
    {
        $days = app(Config::class)->optionalInt('events_days_retain');
        if ($days === null || $days === 0) {
            return;
        }
        try {
            self::query()->where('event_date', '<', NaiveDateTime::format(Dates::now()->modify("-{$days} days")))->delete();
        } catch (QueryException) {
            throw ApiError::message('Error cleaning old events');
        }
    }
}
