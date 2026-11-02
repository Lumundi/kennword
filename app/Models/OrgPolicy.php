<?php

namespace App\Models;

use App\Config\Config;
use App\Http\ApiError;
use App\Http\Controllers\TwoFactor\EmailController;
use App\Http\Json;
use App\Mail\Mail;
use App\Support\Dates;
use App\Support\JsonValue;
use App\Support\Random;
use DateTimeImmutable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Query\JoinClause;
use Illuminate\Database\QueryException;
use stdClass;

/**
 * An organization policy (src/db/models/org_policy.rs). An organization has
 * at most one of each type.
 *
 * @property string $uuid
 * @property string $org_uuid
 * @property int $atype
 * @property bool $enabled
 * @property string $data
 * @property ?DateTimeImmutable $revision_date
 */
final class OrgPolicy extends Model
{
    public const int TYPE_TWO_FACTOR_AUTHENTICATION = 0;

    public const int TYPE_MASTER_PASSWORD = 1;

    public const int TYPE_PASSWORD_GENERATOR = 2;

    public const int TYPE_SINGLE_ORG = 3;

    public const int TYPE_PERSONAL_OWNERSHIP = 5;

    public const int TYPE_DISABLE_SEND = 6;

    public const int TYPE_SEND_OPTIONS = 7;

    public const int TYPE_RESET_PASSWORD = 8;

    public const int TYPE_FILL_ASSIST = 22;

    /**
     * OrgPolicyType: the types Vaultwarden supports.
     */
    public const array TYPES = [0, 1, 2, 3, 5, 6, 7, 8, 14, 15, 16, 17, 20, 22];

    protected $table = 'org_policies';

    protected $primaryKey = 'uuid';

    protected function casts(): array
    {
        return [
            'atype' => 'integer',
            'enabled' => 'boolean',
            'revision_date' => Casts\NaiveDateTime::class,
        ];
    }

    public static function new(string $orgUuid, int $type, bool $enabled, string $data): self
    {
        $policy = new self([
            'uuid' => Random::uuid(),
            'org_uuid' => $orgUuid,
            'atype' => $type,
            'enabled' => $enabled,
            'data' => $data,
            'revision_date' => null,
        ]);
        $policy->revision_date = Dates::now();

        return $policy;
    }

    /**
     * Upstream's REPLACE INTO: another policy of the type goes.
     *
     * @param  array<string, mixed>  $options
     *
     * @throws ApiError
     */
    public function save(array $options = []): bool
    {
        $this->revision_date = Dates::now();
        try {
            self::query()->where('org_uuid', $this->org_uuid)->where('atype', $this->atype)->where('uuid', '!=', $this->uuid)->delete();
        } catch (QueryException) {
            throw ApiError::message('Error saving org_policy');
        }
        $this->upsertRow(['uuid'], 'Error saving org_policy');

        return true;
    }

    /**
     * @return Collection<int, self>
     */
    public static function findByOrg(string $orgUuid): Collection
    {
        return self::query()->where('org_uuid', $orgUuid)->get();
    }

    /**
     * @throws ApiError
     */
    public static function deleteAllByOrganization(string $orgUuid): void
    {
        try {
            self::query()->where('org_uuid', $orgUuid)->delete();
        } catch (QueryException) {
            throw ApiError::message('Error deleting org_policy');
        }
    }

    /**
     * Whether an enabled policy binds the user: a confirmed member below admin.
     */
    public static function isApplicableToUser(string $userUuid, int $policyType, ?string $excludeOrgUuid = null): bool
    {
        foreach (self::findAcceptedAndConfirmedByUserAndActivePolicy($userUuid, $policyType) as $policy) {
            if ($excludeOrgUuid !== null && $policy->org_uuid === $excludeOrgUuid) {
                continue;
            }

            $member = Membership::query()->where('user_uuid', $userUuid)->where('org_uuid', $policy->org_uuid)
                ->where('status', Membership::STATUS_CONFIRMED)->first();
            if ($member !== null && $member->typeBelow(Membership::TYPE_ADMIN)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Enabled policies of a type in organizations the user accepted or is confirmed in.
     *
     * @return Collection<int, self>
     */
    public static function findAcceptedAndConfirmedByUserAndActivePolicy(string $userUuid, int $policyType): Collection
    {
        return self::query()
            ->select('org_policies.*')
            ->join('users_organizations', function (JoinClause $join) use ($userUuid): void {
                $join->on('users_organizations.org_uuid', '=', 'org_policies.org_uuid')
                    ->where('users_organizations.user_uuid', '=', $userUuid);
            })
            ->whereIn('users_organizations.status', [Membership::STATUS_ACCEPTED, Membership::STATUS_CONFIRMED])
            ->where('org_policies.atype', $policyType)
            ->where('org_policies.enabled', true)
            ->get();
    }

    /**
     * Whether a Send Options policy, in an organization where the user is a
     * confirmed member below admin, forbids hiding the email address.
     */
    public static function isHideEmailDisabled(string $userUuid): bool
    {
        foreach (self::findConfirmedByUserAndActivePolicy($userUuid, self::TYPE_SEND_OPTIONS) as $policy) {
            $member = Membership::query()->where('user_uuid', $userUuid)->where('org_uuid', $policy->org_uuid)
                ->where('status', Membership::STATUS_CONFIRMED)->first();
            if ($member === null || ! $member->typeBelow(Membership::TYPE_ADMIN)) {
                continue;
            }

            // SendOptionsPolicyData { disableHideEmail (alias DisableHideEmail): bool }
            [$ok, $data] = JsonValue::decode($policy->data);
            $values = $ok && $data instanceof stdClass ? array_values(array_intersect_key(get_object_vars($data), ['disableHideEmail' => true, 'DisableHideEmail' => true])) : [];
            if (count($values) !== 1 || ! is_bool($values[0])) {
                logger()->error("Failed to deserialize SendOptionsPolicyData: {$policy->data}");

                continue;
            }
            if ($values[0]) {
                return true;
            }
        }

        return false;
    }

    /**
     * Enabled policies of a type in organizations the user is confirmed in.
     *
     * @return Collection<int, self>
     */
    public static function findConfirmedByUserAndActivePolicy(string $userUuid, int $policyType): Collection
    {
        return self::query()
            ->select('org_policies.*')
            ->join('users_organizations', function (JoinClause $join) use ($userUuid): void {
                $join->on('users_organizations.org_uuid', '=', 'org_policies.org_uuid')
                    ->where('users_organizations.user_uuid', '=', $userUuid);
            })
            ->where('users_organizations.status', Membership::STATUS_CONFIRMED)
            ->where('org_policies.atype', $policyType)
            ->where('org_policies.enabled', true)
            ->get();
    }

    /**
     * OrgPolicy::to_json
     *
     * @return array<string, mixed>
     */
    public function toApi(): array
    {
        [$ok, $data] = JsonValue::decode($this->data);
        $policy = [
            'id' => $this->uuid,
            'organizationId' => $this->org_uuid,
            'type' => $this->atype,
            'data' => $ok ? JsonValue::toArrays($data) : null,
            'enabled' => $this->enabled,
            'revisionDate' => $this->revision_date === null ? null : Dates::format($this->revision_date),
            'object' => 'policy',
        ];
        // Like upstream, the reset password policy may always be toggled.
        if ($this->atype === self::TYPE_RESET_PASSWORD) {
            $policy['canToggleState'] = true;
        }

        return Json::sorted($policy);
    }

    public static function findByOrgAndType(string $orgUuid, int $policyType): ?self
    {
        return self::query()->where('org_uuid', $orgUuid)->where('atype', $policyType)->first();
    }

    /**
     * Policies of organizations the user is confirmed in, enabled or not.
     *
     * @return Collection<int, self>
     */
    public static function findConfirmedByUser(string $userUuid): Collection
    {
        return self::ofMemberships($userUuid, [Membership::STATUS_CONFIRMED]);
    }

    /**
     * @return Collection<int, self>
     */
    public static function findAcceptedAndConfirmedByUser(string $userUuid): Collection
    {
        return self::ofMemberships($userUuid, [Membership::STATUS_ACCEPTED, Membership::STATUS_CONFIRMED]);
    }

    /**
     * OrgPolicy::check_user_allowed: users and managers who take part may
     * have to use two-factor login, and a single organization policy keeps
     * them out of other organizations.
     *
     * @throws ApiError
     */
    public static function checkUserAllowed(Membership $member, string $action): void
    {
        if (! $member->typeBelow(Membership::TYPE_ADMIN) || $member->status <= Membership::STATUS_INVITED) {
            return;
        }

        $twoFactor = self::findByOrgAndType($member->org_uuid, self::TYPE_TWO_FACTOR_AUTHENTICATION);
        if ($twoFactor !== null && $twoFactor->enabled && TwoFactor::findByUser($member->user_uuid)->isEmpty()) {
            if (! app(Config::class)->bool('email_2fa_auto_fallback')) {
                throw ApiError::message("Cannot {$action} because 2FA is required (membership {$member->uuid})");
            }
            EmailController::findAndActivateEmail2fa($member->user_uuid);
        }

        if (self::isApplicableToUser($member->user_uuid, self::TYPE_SINGLE_ORG, $member->org_uuid)) {
            throw ApiError::message("Cannot {$action} because another organization policy forbids it (membership {$member->uuid})");
        }

        $singleOrg = self::findByOrgAndType($member->org_uuid, self::TYPE_SINGLE_ORG);
        if ($singleOrg !== null && $singleOrg->enabled && Membership::countAcceptedAndConfirmedByUser($member->user_uuid, $member->org_uuid) > 0) {
            throw ApiError::message("Cannot {$action} because the organization policy forbids being part of other organization (membership {$member->uuid})");
        }
    }

    /**
     * two_factor::enforce_2fa_policy: the user, now without two-factor login,
     * is revoked from organizations below admin that require it.
     *
     * @throws ApiError
     */
    public static function enforceTwoFactorForUser(User $user, string $actUserUuid, int $deviceType, string $ip): void
    {
        foreach (Membership::findByUserAndPolicy($user->uuid, self::TYPE_TWO_FACTOR_AUTHENTICATION) as $member) {
            if (! $member->typeBelow(Membership::TYPE_ADMIN)) {
                continue;
            }
            if (app(Config::class)->mailEnabled()) {
                $org = Organization::findByUuid($member->org_uuid) ?? throw new \LogicException("Organization {$member->org_uuid} is missing");
                Mail::send2faRemovedFromOrg($user->email, $org->name);
            }
            $member->revoke();
            $member->save();
            Event::log(Event::ORGANIZATION_USER_REVOKED_TWO_FACTOR_NON_COMPLIANCE, $member->uuid, $member->org_uuid, $actUserUuid, $deviceType, $ip);
        }
    }

    /**
     * two_factor::enforce_2fa_policy_for_org: confirmed members below admin
     * without two-factor login are revoked.
     *
     * @throws ApiError
     */
    public static function enforceTwoFactorForOrg(string $orgUuid, string $actUserUuid, int $deviceType, string $ip): void
    {
        $org = Organization::findByUuid($orgUuid) ?? throw new \LogicException("Organization {$orgUuid} is missing");
        foreach (Membership::findConfirmedByOrg($orgUuid) as $member) {
            if (! $member->typeBelow(Membership::TYPE_ADMIN) || TwoFactor::findByUser($member->user_uuid)->isNotEmpty()) {
                continue;
            }
            if (app(Config::class)->mailEnabled()) {
                $user = User::findByUuid($member->user_uuid) ?? throw new \LogicException("User {$member->user_uuid} is missing");
                Mail::send2faRemovedFromOrg($user->email, $org->name);
            }
            $member->revoke();
            $member->save();
            Event::log(Event::ORGANIZATION_USER_REVOKED_TWO_FACTOR_NON_COMPLIANCE, $member->uuid, $member->org_uuid, $actUserUuid, $deviceType, $ip);
        }
    }

    /**
     * @param  list<int>  $statuses
     * @return Collection<int, self>
     */
    private static function ofMemberships(string $userUuid, array $statuses): Collection
    {
        return self::query()
            ->select('org_policies.*')
            ->join('users_organizations', function (JoinClause $join) use ($userUuid): void {
                $join->on('users_organizations.org_uuid', '=', 'org_policies.org_uuid')
                    ->where('users_organizations.user_uuid', '=', $userUuid);
            })
            ->whereIn('users_organizations.status', $statuses)
            ->get();
    }
}
