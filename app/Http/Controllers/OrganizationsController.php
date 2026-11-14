<?php

namespace App\Http\Controllers;

use App\Auth\AdminHeaders;
use App\Auth\Headers;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\ManagerHeaders;
use App\Auth\ManagerHeadersLoose;
use App\Auth\OrgHeaders;
use App\Auth\OrgMemberHeaders;
use App\Auth\OwnerHeaders;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Controllers\TwoFactor\EmailController;
use App\Http\Data\AuthenticationData;
use App\Http\Data\Body;
use App\Http\Data\CipherData;
use App\Http\Data\Fields;
use App\Http\Data\NumberOrString;
use App\Http\Data\PasswordOrOtpData;
use App\Http\Data\Query;
use App\Http\Data\UnlockData;
use App\Http\EmptyResponse;
use App\Http\HttpStatus;
use App\Http\Json;
use App\Mail\Mail;
use App\Models\Cipher;
use App\Models\CollectionCipher;
use App\Models\CollectionGroup;
use App\Models\CollectionUser;
use App\Models\Device;
use App\Models\Event;
use App\Models\Group;
use App\Models\GroupUser;
use App\Models\Invitation;
use App\Models\Membership;
use App\Models\Organization;
use App\Models\OrganizationApiKey;
use App\Models\OrgCollection;
use App\Models\OrgPolicy;
use App\Models\TwoFactor;
use App\Models\User;
use App\Notifications\Notify;
use App\Support\CheckedInt;
use App\Support\Dates;
use App\Support\EscapeDebug;
use App\Support\JsonValue;
use App\Support\UpdateType;
use App\Support\Uuid;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use stdClass;
use Uri\WhatWg\Url;

/**
 * src/api/core/organizations.rs: organizations, their members, collections,
 * groups, policies, account recovery, API keys, import and export. The
 * mails are not ported yet (account recovery needs them), so the accept
 * route that the invitation links lead to is missing too.
 */
final readonly class OrganizationsController
{
    /**
     * admin::FAKE_ADMIN_UUID: the organization of invitations from the admin panel.
     */
    private const string FAKE_ADMIN_UUID = '00000000-0000-0000-0000-000000000000';

    /**
     * sso::FAKE_SSO_IDENTIFIER
     */
    private const string FAKE_SSO_IDENTIFIER = '00000000-01DC-01DC-01DC-000000000000';

    public function __construct(
        private Config $config,
        private Jwt $jwt,
        private Notify $nt,
    ) {}

    /**
     * POST /api/organizations: the creator becomes its confirmed owner, with
     * a first collection.
     */
    public function createOrganization(Headers $headers, Request $request): Response
    {
        $body = Body::json($request);
        $billingEmail = $body->string('billingEmail');
        $collectionName = $body->string('collectionName');
        $key = $body->string('key');
        $name = $body->string('name');
        $keys = $body->optionalObject('keys');
        [$privateKey, $publicKey] = $keys === null ? [null, null] : [$keys->string('encryptedPrivateKey'), $keys->string('publicKey')];
        // The plan is ignored, always the same.
        NumberOrString::optional($body, 'planType') ?? throw new HttpStatus(422, 'Missing field `planType`.');

        if (! $this->config->isOrgCreationAllowed($headers->user->email)) {
            throw ApiError::message('User not allowed to create organizations');
        }
        if (OrgPolicy::isApplicableToUser($headers->user->uuid, OrgPolicy::TYPE_SINGLE_ORG)) {
            throw ApiError::message('You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization.');
        }

        $org = Organization::new($name, $billingEmail, $privateKey, $publicKey);
        $member = Membership::new($headers->user->uuid, $org->uuid, null);
        $collection = OrgCollection::new($org->uuid, $collectionName, null);
        $member->akey = $key;
        $member->access_all = true;
        $member->atype = Membership::TYPE_OWNER;
        $member->status = Membership::STATUS_CONFIRMED;

        $org->save();
        $member->save();
        $collection->save();

        return Json::response($org->toApi());
    }

    /**
     * DELETE /api/organizations/{org_id}: with everything in it.
     */
    public function deleteOrganization(OwnerHeaders $headers, Request $request, string $orgId): EmptyResponse
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $data = PasswordOrOtpData::fromFields(Body::json($request));
        $data->validate($headers->user, true, $this->config);

        $org = Organization::findByUuid($orgId) ?? throw ApiError::message('Organization not found');
        $org->deleteOrganization();

        return new EmptyResponse;
    }

    /**
     * POST /api/organizations/{org_id}/leave
     */
    public function leaveOrganization(OrgMemberHeaders $headers, Request $request, string $orgId): EmptyResponse
    {
        $orgId = Uuid::parameter($request, $orgId);
        $membership = $headers->membership;
        if ($membership->status !== Membership::STATUS_CONFIRMED) {
            throw ApiError::message('You need to be a Member of the Organization to call this endpoint');
        }
        if ($membership->atype === Membership::TYPE_OWNER && Membership::countConfirmedByOrgAndType($orgId, Membership::TYPE_OWNER) <= 1) {
            throw ApiError::message("The last owner can't leave");
        }

        self::logEvent(Event::ORGANIZATION_USER_LEFT, $membership->uuid, $orgId, $headers);
        $membership->deleteMembership();

        return new EmptyResponse;
    }

    /**
     * GET /api/organizations/{org_id}
     */
    public function getOrganization(OwnerHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $org = Organization::findByUuid($orgId) ?? throw ApiError::message("Can't find organization details");

        return Json::response($org->toApi());
    }

    /**
     * PUT /api/organizations/{org_id}
     */
    public function putOrganization(OwnerHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $body = Body::json($request);
        $billingEmail = $body->string('billingEmail');
        $name = $body->string('name');

        $org = Organization::findByUuid($orgId) ?? throw ApiError::message('Organization not found');
        $org->name = $name;
        $org->billing_email = mb_strtolower($billingEmail);
        $org->save();
        self::logEvent(Event::ORGANIZATION_UPDATED, $orgId, $orgId, $headers);

        return Json::response($org->toApi());
    }

    /**
     * POST /api/organizations/{org_id}/keys: the organization's key pair, once.
     */
    public function postOrgKeys(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $body = Body::json($request);
        $privateKey = $body->string('encryptedPrivateKey');
        $publicKey = $body->string('publicKey');

        $org = Organization::findByUuid($orgId) ?? throw ApiError::message("Can't find organization details");
        if ($org->private_key !== null && $org->public_key !== null) {
            throw ApiError::message('Organization Keys already exist');
        }
        $org->private_key = $privateKey;
        $org->public_key = $publicKey;
        $org->save();

        return Json::response(Json::sorted(['object' => 'organizationKeys', 'publicKey' => $org->public_key, 'privateKey' => $org->private_key]));
    }

    /**
     * GET /api/organizations/{org_id}/public-key, also the older /keys
     */
    public function getOrganizationPublicKey(OrgMemberHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $org = Organization::findByUuid($orgId) ?? throw ApiError::message('Organization not found');

        return Json::response(Json::sorted(['object' => 'organizationPublicKey', 'publicKey' => $org->public_key]));
    }

    /**
     * GET /api/collections: every collection the user reaches.
     */
    public function getUserCollections(Headers $headers): Response
    {
        $collections = OrgCollection::findByUserUuid($headers->user->uuid)->map(static fn (OrgCollection $collection): array => $collection->toApi())->all();

        return Json::response(Json::sorted(['data' => array_values($collections), 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * GET /api/organizations/{org_id}/collections
     */
    public function getOrgCollections(ManagerHeadersLoose $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        if (! $headers->membership->hasFullAccess()) {
            throw ApiError::message('Resource not found.', 404, 'User does not have full access');
        }

        $collections = OrgCollection::findByOrganization($orgId)->map(static fn (OrgCollection $collection): array => $collection->toApi())->all();

        return Json::response(Json::sorted(['data' => array_values($collections), 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * GET /api/organizations/{org_id}/collections/details: the collections the
     * user is assigned to (all of them with full access), with who may use them.
     */
    public function getOrgCollectionsDetails(ManagerHeadersLoose $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $member = Membership::findByUserAndOrg($headers->user->uuid, $orgId) ?? throw ApiError::message('User is not part of organization');

        $accesses = CollectionUser::findByOrganizationSwapUserUuidWithMemberUuid($orgId);
        $types = self::membershipTypes($orgId);
        $groups = Group::enabled();
        $fullAccess = $member->hasFullAccess() || ($groups && GroupUser::hasFullAccessByMember($orgId, $member->uuid));

        // Owners, admins and managers with access to all are listed as well.
        $manageAll = array_values(Membership::findConfirmedAndManageAllByOrg($orgId)->map(static fn (Membership $manager): array => [
            'hidePasswords' => false, 'id' => $manager->uuid, 'manage' => true, 'readOnly' => false,
        ])->all());

        $data = [];
        foreach (OrgCollection::findByOrganization($orgId) as $collection) {
            $assigned = $fullAccess
                || CollectionUser::hasAccessToCollectionByUser($collection->uuid, $member->user_uuid)
                || ($groups && GroupUser::hasAccessToCollectionByMember($collection->uuid, $member->uuid));
            if (! $assigned) {
                continue;
            }

            $users = [];
            foreach ($accesses as $access) {
                if ($access->collectionUuid === $collection->uuid) {
                    $users[] = $access->toApiDetailsForMember($types[$access->userUuid] ?? Membership::TYPE_USER);
                }
            }

            $data[] = Json::sorted([
                ...$collection->toApiDetails($headers->user->uuid),
                'assigned' => $assigned,
                'users' => [...$users, ...$manageAll],
                'groups' => self::collectionGroups($collection->uuid),
                'object' => 'collectionAccessDetails',
                'unmanaged' => false,
            ]);
        }

        return Json::response(Json::sorted(['data' => $data, 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * POST /api/organizations/{org_id}/collections
     */
    public function postOrganizationCollections(ManagerHeadersLoose $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        [$name, $groups, $users, $externalId] = self::fullCollectionData(Body::json($request));
        self::validateCollectionAccess($orgId, $groups, $users);

        if ($headers->membership->atype === Membership::TYPE_MANAGER && ! $headers->membership->access_all) {
            throw ApiError::message("You don't have permission to create collections");
        }

        $collection = OrgCollection::new($orgId, $name, $externalId);
        $collection->save();
        self::logEvent(Event::COLLECTION_CREATED, $collection->uuid, $orgId, $headers);
        self::saveCollectionAccess($orgId, $collection->uuid, $groups, $users);

        return Json::response($collection->toApiDetails($headers->membership->user_uuid));
    }

    /**
     * POST /api/organizations/{org_id}/collections/bulk-access: replaces who
     * may use each of the collections.
     */
    public function postBulkAccessCollections(ManagerHeadersLoose $headers, Request $request, string $orgId): EmptyResponse
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $body = Body::json($request);
        $collectionIds = $body->stringList('collectionIds');
        $groups = array_map(self::collectionAccessData(...), $body->objectList('groups'));
        $users = array_map(self::collectionAccessData(...), $body->objectList('users'));

        Organization::findByUuid($orgId) ?? throw ApiError::message("Can't find organization details");
        self::validateGroups($orgId, $groups);

        foreach ($collectionIds as $collectionId) {
            $collection = OrgCollection::findByUuidAndOrg($collectionId, $orgId) ?? throw ApiError::message('Collection not found');
            if (! $collection->isManageableByUser($headers->membership->user_uuid)) {
                throw ApiError::message('Collection not found', logMessage: "The current user isn't a manager for this collection");
            }
            // Bumps the revision of everyone with access.
            $collection->save();
            self::logEvent(Event::COLLECTION_UPDATED, $collection->uuid, $orgId, $headers);

            self::replaceCollectionAccess($orgId, $collectionId, $groups, $users);
        }

        return new EmptyResponse;
    }

    /**
     * PUT /api/organizations/{org_id}/collections/{col_id}
     */
    public function putOrganizationCollectionUpdate(ManagerHeaders $headers, Request $request, string $orgId, string $colId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $colId = Uuid::parameter($request, $colId);
        [$name, $groups, $users, $externalId] = self::fullCollectionData(Body::json($request));
        self::validateCollectionAccess($orgId, $groups, $users);

        Organization::findByUuid($orgId) ?? throw ApiError::message("Can't find organization details");
        $collection = OrgCollection::findByUuidAndOrg($colId, $orgId) ?? throw ApiError::message('Collection not found');

        $collection->name = $name;
        $collection->external_id = $externalId === null || trim($externalId) === '' ? null : $externalId;
        $collection->save();
        self::logEvent(Event::COLLECTION_UPDATED, $collection->uuid, $orgId, $headers);

        self::replaceCollectionAccess($orgId, $colId, $groups, $users);

        return Json::response($collection->toApiDetails($headers->user->uuid));
    }

    /**
     * DELETE /api/organizations/{org_id}/collections/{col_id}
     */
    public function deleteOrganizationCollection(ManagerHeaders $headers, Request $request, string $orgId, string $colId): EmptyResponse
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $this->deleteCollection($orgId, Uuid::parameter($request, $colId), $headers);

        return new EmptyResponse;
    }

    /**
     * DELETE /api/organizations/{org_id}/collections: several, each of which
     * the user must manage.
     */
    public function bulkDeleteOrganizationCollections(ManagerHeadersLoose $headers, Request $request, string $orgId): EmptyResponse
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $collectionIds = Body::json($request)->stringList('ids');

        // ManagerHeaders::from_loose
        foreach ($collectionIds as $collectionId) {
            if (! Uuid::isValid($collectionId)) {
                throw ApiError::message('Collection Id is malformed!');
            }
            if (! OrgCollection::isCollManageableByUser($collectionId, $headers->membership->user_uuid)) {
                throw ApiError::message('Collection not found', logMessage: "The current user isn't a manager for this collection");
            }
        }

        foreach ($collectionIds as $collectionId) {
            $this->deleteCollection($orgId, $collectionId, $headers);
        }

        return new EmptyResponse;
    }

    /**
     * GET /api/organizations/{org_id}/collections/{col_id}/details
     */
    public function getOrgCollectionDetail(ManagerHeaders $headers, Request $request, string $orgId, string $colId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $colId = Uuid::parameter($request, $colId);

        $collection = OrgCollection::findByUuidAndUser($colId, $headers->user->uuid) ?? throw ApiError::message('Collection not found');
        if ($collection->org_uuid !== $orgId) {
            throw ApiError::message('Collection is not owned by organization');
        }
        $member = Membership::findByUserAndOrg($headers->user->uuid, $orgId) ?? throw ApiError::message('User is not part of organization');

        $types = self::membershipTypes($orgId);
        $users = array_map(
            static fn (CollectionUser $access): array => $access->toApiDetailsForMember($types[$access->userUuid] ?? Membership::TYPE_USER),
            CollectionUser::findByOrgAndCollSwapUserUuidWithMemberUuid($orgId, $collection->uuid),
        );

        return Json::response(Json::sorted([
            ...$collection->toApiDetails($headers->user->uuid),
            'assigned' => OrgCollection::canAccessCollection($member, $collection->uuid),
            'users' => $users,
            'groups' => self::collectionGroups($collection->uuid),
            'object' => 'collectionAccessDetails',
        ]));
    }

    /**
     * GET /api/organizations/{org_id}/collections/{col_id}/users
     */
    public function getCollectionUsers(ManagerHeaders $headers, Request $request, string $orgId, string $colId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $colId = Uuid::parameter($request, $colId);
        $collection = OrgCollection::findByUuidAndOrg($colId, $orgId) ?? throw ApiError::message('Collection not found in Organization');

        $members = [];
        foreach (CollectionUser::findByCollection($collection->uuid) as $access) {
            $member = Membership::findByUserAndOrg($access->userUuid, $orgId) ?? throw new \LogicException("No membership for {$access->userUuid}");
            $members[] = $member->toApiUserAccessRestrictions($access);
        }

        return Json::response($members);
    }

    /**
     * GET /api/organizations/{org_id}/users
     */
    public function getMembers(ManagerHeadersLoose $headers, Request $request, string $orgId): Response
    {
        $includeCollections = self::optionalQueryBool($request, 'includeCollections');
        $includeGroups = self::optionalQueryBool($request, 'includeGroups');
        $orgId = $this->orgId($request, $orgId, $headers);
        if (! $headers->membership->hasFullAccess()) {
            throw ApiError::message('Resource not found.', 404, 'User does not have full access');
        }

        $members = Membership::findByOrg($orgId)->map(static fn (Membership $member): array => $member->toApiDetailsForAdmin($includeCollections ?? false, $includeGroups ?? false))->all();

        return Json::response(Json::sorted(['data' => array_values($members), 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * GET /api/organizations/{org_id}/users/mini-details
     */
    public function getOrgUserMiniDetails(ManagerHeadersLoose $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $members = Membership::findByOrg($orgId)->map(static fn (Membership $member): array => $member->toApiMiniDetails())->all();

        return Json::response(Json::sorted(['data' => array_values($members), 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * GET /api/organizations/{org_id}/users/{member_id}
     */
    public function getUser(AdminHeaders $headers, Request $request, string $orgId, string $memberId): Response
    {
        $includeCollections = self::optionalQueryBool($request, 'includeCollections');
        // With groups the collections must come too, or saving would lose them.
        $includeGroups = self::optionalQueryBool($request, 'includeGroups') ?? false;
        $orgId = $this->orgId($request, $orgId, $headers);
        $memberId = Uuid::parameter($request, $memberId);

        $member = Membership::findByUuidAndOrg($memberId, $orgId) ?? throw ApiError::message("The specified user isn't a member of the organization");

        return Json::response($member->toApiDetailsForAdmin($includeCollections ?? $includeGroups, $includeGroups));
    }

    /**
     * POST /api/organizations/{org_id}/users/invite: without mail, existing
     * users join as accepted, new ones get an invitation to register.
     */
    public function sendInvite(AdminHeaders $headers, Request $request, string $orgId): EmptyResponse
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $body = Body::json($request);
        $emails = $body->stringList('emails');
        $groups = $body->stringList('groups');
        $rawType = self::rawType($body);
        $collectionsField = $body->value('collections');
        $collections = $collectionsField === null ? [] : array_map(self::collectionAccessData(...), $body->objectList('collections'));
        $permissions = self::permissions($body);

        // InviteData::validate
        $orgCollections = OrgCollection::findByOrganization($orgId)->pluck('uuid')->all();
        foreach ($collections as $collection) {
            if (! in_array($collection['id'], $orgCollections, true)) {
                throw ApiError::message('Invalid collection', logMessage: 'Collection '.EscapeDebug::of($collection['id'])." does not belong to organization {$orgId}!");
            }
        }
        $orgGroups = self::groupIds($orgId);
        foreach ($groups as $group) {
            if (! in_array($group, $orgGroups, true)) {
                throw ApiError::message('Invalid group', logMessage: 'Group '.EscapeDebug::of($group)." does not belong to organization {$orgId}!");
            }
        }

        $newType = Membership::typeFromString($rawType) ?? throw ApiError::message('Invalid type');
        if ($newType !== Membership::TYPE_USER && $headers->membership->atype !== Membership::TYPE_OWNER) {
            throw ApiError::message('Only Owners can invite Managers, Admins or Owners');
        }
        $accessAll = self::accessAll($newType, $rawType, $permissions);

        foreach ($emails as $email) {
            $status = Membership::STATUS_INVITED;
            $user = User::findByMail($email);
            $created = $user === null;
            if ($user === null) {
                if (! $this->config->bool('invitations_allowed')) {
                    throw ApiError::message('User does not exist: '.EscapeDebug::of($email));
                }
                if (! $this->config->isEmailDomainAllowed($email)) {
                    throw ApiError::message('Email domain not eligible for invitations');
                }
                if (! $this->config->mailEnabled()) {
                    Invitation::new($email)->save();
                }
                $user = User::new($email);
                $user->save();
            } else {
                if (Membership::findByUserAndOrg($user->uuid, $orgId) !== null) {
                    throw ApiError::message('User already in organization: '.EscapeDebug::of($email));
                }
                if (! $this->config->mailEnabled()) {
                    if ($user->password_hash === '') {
                        Invitation::new($email)->save();
                    } else {
                        // Without mail, existing users accept right away.
                        $status = Membership::STATUS_ACCEPTED;
                    }
                }
            }

            $member = Membership::new($user->uuid, $orgId, $headers->user->email);
            $member->access_all = $accessAll;
            $member->atype = $newType;
            $member->status = $status;
            $member->save();

            if ($this->config->mailEnabled()) {
                $org = Organization::findByUuid($orgId) ?? throw ApiError::message('Error looking up organization');
                try {
                    Mail::sendInvite($user, $orgId, $member->uuid, $org->name, $headers->user->email);
                } catch (ApiError $error) {
                    // Undo what the invitation added.
                    if ($created) {
                        $user->deleteUser();
                    } else {
                        $member->deleteMembership();
                    }

                    throw ApiError::message("Error sending invite: {$error->debugText()} ");
                }
            }

            self::logEvent(Event::ORGANIZATION_USER_INVITED, $member->uuid, $orgId, $headers);

            if (! $accessAll) {
                foreach ($collections as $collection) {
                    OrgCollection::findByUuidAndOrg($collection['id'], $orgId) ?? throw ApiError::message('Collection not found in Organization');
                    CollectionUser::save($user->uuid, $collection['id'], $collection['readOnly'], $collection['hidePasswords'], $collection['manage']);
                }
            }

            foreach ($groups as $group) {
                self::addToGroup($orgId, $group, $member->uuid);
            }
        }

        return new EmptyResponse;
    }

    /**
     * POST /api/organizations/{org_id}/users/{member_id}/accept: the invited
     * user accepts with the mailed token, which names the organization and
     * the membership.
     */
    public function acceptInvite(Headers $headers, Request $request, string $orgId, string $memberId): EmptyResponse
    {
        $orgId = Uuid::parameter($request, $orgId);
        $memberId = Uuid::parameter($request, $memberId);
        $body = Body::json($request);
        $token = $body->string('token');
        $resetPasswordKey = $body->optionalString('resetPasswordKey');

        $claims = $this->jwt->decode($token, JwtIssuer::Invite, fields: Jwt::INVITE_CLAIMS);
        // Nobody else may accept the invitation.
        if ($claims['email'] !== $headers->user->email) {
            throw ApiError::message('Invitation was issued to a different account', logMessage: 'Claim does not match user_id');
        }
        if ($claims['org_id'] !== $orgId) {
            throw ApiError::message('Error accepting the invitation', logMessage: 'Claim does not match the org_id');
        }
        if ($claims['member_id'] !== $memberId) {
            throw ApiError::message('Error accepting the invitation', logMessage: 'Claim does not match the member_id');
        }
        Invitation::take($claims['email']);

        // Invitations from the admin panel need no acceptance.
        if ($claims['member_id'] === self::FAKE_ADMIN_UUID) {
            if ($this->config->mailEnabled()) {
                Mail::sendInviteConfirmed($claims['email'], $this->config->string('invitation_org_name'));
            }

            return new EmptyResponse;
        }

        $membership = Membership::findByUuidAndOrg($claims['member_id'], $claims['org_id']) ?? throw ApiError::message('Error accepting the invitation');
        if ($this->orgIsResetPasswordAutoEnroll($membership->org_uuid)) {
            $resetPasswordKey ?? throw ApiError::message('Reset password key is required, but not provided.');
        } else {
            $resetPasswordKey = null;
        }
        // For members invited before the inviter was stored.
        $membership->invited_by_email ??= is_string($claims['invited_by_email']) ? $claims['invited_by_email'] : null;

        self::acceptOrgInvite($headers->user, $membership, $resetPasswordKey);

        return new EmptyResponse;
    }

    /**
     * POST /api/organizations/{org_id}/users/{member_id}/reinvite
     */
    public function reinviteMember(AdminHeaders $headers, Request $request, string $orgId, string $memberId): EmptyResponse
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $this->reinvite($orgId, Uuid::parameter($request, $memberId), $headers->user->email);

        return new EmptyResponse;
    }

    /**
     * POST /api/organizations/{org_id}/users/reinvite
     */
    public function bulkReinviteMembers(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $ids = Body::json($request)->stringList('ids');

        return self::bulkResponse($ids, 'OrganizationBulkConfirmResponseModel', 'reinvite', fn (string $id) => $this->reinvite($orgId, $id, $headers->user->email));
    }

    /**
     * POST /api/organizations/{org_id}/users/{member_id}/confirm
     */
    public function confirmInvite(AdminHeaders $headers, Request $request, string $orgId, string $memberId): EmptyResponse
    {
        $memberId = Uuid::parameter($request, $memberId);
        $orgId = Uuid::parameter($request, $orgId);
        $body = Body::json($request);
        $body->optionalString('id');
        $key = $body->optionalString('key') ?? '';

        $this->confirm($orgId, $memberId, $key, $headers);

        return new EmptyResponse;
    }

    /**
     * POST /api/organizations/{org_id}/users/confirm
     */
    public function bulkConfirmInvite(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $body = Body::json($request);
        $keys = $body->value('keys') === null ? null : $body->objectList('keys');
        $invites = array_map(static fn (Fields $invite): array => [$invite->optionalString('id'), $invite->optionalString('key')], $keys ?? []);

        $responses = [];
        foreach ($invites as [$memberId, $key]) {
            $memberId ?? throw ApiError::message('Member id is required');
            $responses[] = self::bulkItem($memberId, 'OrganizationBulkConfirmResponseModel', 'confirm', fn () => $this->confirm($orgId, $memberId, $key ?? '', $headers));
        }
        if ($keys === null) {
            logger()->error('No keys to confirm');
        }

        return Json::response(Json::sorted(['data' => $responses, 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * PUT /api/organizations/{org_id}/users/{member_id}: type and collections.
     */
    public function editMember(AdminHeaders $headers, Request $request, string $orgId, string $memberId): EmptyResponse
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $memberId = Uuid::parameter($request, $memberId);
        $body = Body::json($request);
        $rawType = self::rawType($body);
        $collections = $body->value('collections') === null ? [] : array_map(self::collectionAccessData(...), $body->objectList('collections'));
        $groups = $body->value('groups') === null ? [] : $body->stringList('groups');
        $permissions = self::permissions($body);

        $newType = Membership::typeFromString($rawType) ?? throw ApiError::message('Invalid type');
        $accessAll = self::accessAll($newType, $rawType, $permissions);

        $member = Membership::findByUuidAndOrg($memberId, $orgId) ?? throw ApiError::message("The specified user isn't member of the organization");

        if ($newType !== $member->atype
            && (Membership::typeAtLeast($member->atype, Membership::TYPE_ADMIN) || Membership::typeAtLeast($newType, Membership::TYPE_ADMIN))
            && $headers->membership->atype !== Membership::TYPE_OWNER) {
            throw ApiError::message('Only Owners can grant and remove Admin or Owner privileges');
        }
        if ($member->atype === Membership::TYPE_OWNER && $headers->membership->atype !== Membership::TYPE_OWNER) {
            throw ApiError::message('Only Owners can edit Owner users');
        }
        if ($member->atype === Membership::TYPE_OWNER && $newType !== Membership::TYPE_OWNER && $member->status === Membership::STATUS_CONFIRMED
            && Membership::countConfirmedByOrgAndType($orgId, Membership::TYPE_OWNER) <= 1) {
            throw ApiError::message("Can't delete the last owner");
        }

        $member->access_all = $accessAll;
        $member->atype = $newType;
        // After the change: admins are exempt.
        OrgPolicy::checkUserAllowed($member, 'modify');

        foreach (CollectionUser::findByOrganizationAndUserUuid($orgId, $member->user_uuid) as $access) {
            $access->delete();
        }
        if (! $accessAll) {
            foreach ($collections as $collection) {
                OrgCollection::findByUuidAndOrg($collection['id'], $orgId) ?? throw ApiError::message('Collection not found in Organization');
                CollectionUser::save($member->user_uuid, $collection['id'], $collection['readOnly'], $collection['hidePasswords'], $collection['manage']);
            }
        }

        GroupUser::deleteAllByMember($member->uuid);
        foreach ($groups as $group) {
            self::addToGroup($orgId, $group, $member->uuid);
        }

        self::logEvent(Event::ORGANIZATION_USER_UPDATED, $member->uuid, $orgId, $headers);
        $member->save();

        return new EmptyResponse;
    }

    /**
     * DELETE /api/organizations/{org_id}/users/{member_id}
     */
    public function deleteMember(AdminHeaders $headers, Request $request, string $orgId, string $memberId): EmptyResponse
    {
        $memberId = Uuid::parameter($request, $memberId);
        $this->removeMember(Uuid::parameter($request, $orgId), $memberId, $headers);

        return new EmptyResponse;
    }

    /**
     * DELETE /api/organizations/{org_id}/users
     */
    public function bulkDeleteMember(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $ids = Body::json($request)->stringList('ids');

        return self::bulkResponse($ids, 'OrganizationBulkConfirmResponseModel', 'delete', fn (string $id) => $this->removeMember($orgId, $id, $headers));
    }

    /**
     * POST /api/organizations/{org_id}/users/public-keys: of the members that exist.
     */
    public function bulkPublicKeys(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $ids = Body::json($request)->stringList('ids');

        $keys = [];
        foreach ($ids as $id) {
            $member = Membership::findByUuidAndOrg($id, $orgId);
            $user = $member === null ? null : User::findByUuid($member->user_uuid);
            if ($user !== null) {
                $keys[] = Json::sorted(['object' => 'organizationUserPublicKeyResponseModel', 'id' => $id, 'userId' => $user->uuid, 'key' => $user->public_key]);
            }
        }

        return Json::response(Json::sorted(['data' => $keys, 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * PUT /api/organizations/{org_id}/users/{member_id}/revoke
     */
    public function revokeMember(AdminHeaders $headers, Request $request, string $orgId, string $memberId): EmptyResponse
    {
        $memberId = Uuid::parameter($request, $memberId);
        $this->revoke(Uuid::parameter($request, $orgId), $memberId, $headers);

        return new EmptyResponse;
    }

    /**
     * PUT /api/organizations/{org_id}/users/revoke
     */
    public function bulkRevokeMembers(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $body = Body::json($request);
        $ids = $body->value('ids') === null ? null : $body->stringList('ids');
        if ($ids === null) {
            logger()->error('No users to revoke');
        }

        return self::bulkResponse($ids ?? [], 'OrganizationUserBulkResponseModel', 'revoke', fn (string $id) => $this->revoke($orgId, $id, $headers));
    }

    /**
     * PUT /api/organizations/{org_id}/users/{member_id}/restore, also /restore/vnext,
     * which sends a default collection name that is not supported.
     */
    public function restoreMember(AdminHeaders $headers, Request $request, string $orgId, string $memberId): EmptyResponse
    {
        $memberId = Uuid::parameter($request, $memberId);
        $this->restore(Uuid::parameter($request, $orgId), $memberId, $headers);

        return new EmptyResponse;
    }

    /**
     * PUT /api/organizations/{org_id}/users/restore
     */
    public function bulkRestoreMembers(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $ids = Body::json($request)->stringList('ids');

        return self::bulkResponse($ids, 'OrganizationUserBulkResponseModel', 'restore', fn (string $id) => $this->restore($orgId, $id, $headers));
    }

    /**
     * POST /api/ciphers/bulk-collections: adds the ciphers to the collections,
     * or removes them. Ciphers the user cannot write to are skipped.
     */
    public function postBulkCollections(Headers $headers, Request $request): EmptyResponse
    {
        $body = Body::json($request);
        $orgId = $body->string('organizationId');
        // HashSets: each id once.
        $cipherIds = array_values(array_unique($body->stringList('cipherIds')));
        $collectionIds = array_values(array_unique($body->stringList('collectionIds')));
        $remove = $body->bool('removeCollections');

        Membership::findConfirmedByUserAndOrg($headers->user->uuid, $orgId)
            ?? throw ApiError::message('You need to be a Member of the Organization to call this endpoint');

        $reachable = [];
        foreach (OrgCollection::findByOrganizationAndUserUuid($orgId, $headers->user->uuid) as $collection) {
            $reachable[$collection->uuid] = $collection;
        }
        foreach ($collectionIds as $collectionId) {
            if (! isset($reachable[$collectionId]) || ! $reachable[$collectionId]->isWritableByUser($headers->user->uuid)) {
                throw ApiError::message('Resource not found', 404, 'User does not have access to a collection');
            }
        }

        foreach ($cipherIds as $cipherId) {
            // Gone ciphers are skipped; they may just have been deleted. Unlike Vaultwarden, which only asks for
            // write access, the user needs what PUT /ciphers/{id}/collections asks for: write access with visible
            // passwords, or manage. Otherwise a member could link a cipher whose passwords are hidden from them to
            // a collection where they are not, and read them there.
            $cipher = Cipher::findByUuidAndOrg($cipherId, $orgId);
            if ($cipher === null || ! $cipher->isInEditableCollectionByUser($headers->user->uuid)) {
                continue;
            }
            foreach ($collectionIds as $collectionId) {
                if ($remove) {
                    CollectionCipher::delete($cipher->uuid, $collectionId);
                } else {
                    CollectionCipher::save($cipher->uuid, $collectionId);
                }
            }
        }

        return new EmptyResponse;
    }

    /**
     * GET /api/ciphers/organization-details?organizationId=: the organization's
     * ciphers as an admin sees them.
     */
    public function getOrgDetails(ManagerHeadersLoose $headers, Request $request): Response
    {
        $orgId = Query::first($request, 'organizationId') ?? throw new HttpStatus(404, 'No organizationId.');
        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Resource not found.', 404, "Organization id's do not match");
        }
        if (! $headers->membership->hasFullAccess()) {
            throw ApiError::message('Resource not found.', 404, 'User does not have full access');
        }

        $sync = CiphersController::syncData($headers->user->uuid, organizationView: true);
        $ciphers = Cipher::findByOrg($orgId)->map(static fn (Cipher $cipher): array => $cipher->toApi($headers->host, $headers->user->uuid, $sync, organizationView: true))->all();

        return Json::response(Json::sorted(['data' => array_values($ciphers), 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * PUT /api/organizations/{org_id}/users/{member_id}/recover-account: an
     * admin sets a new master password for an enrolled member, or removes
     * their two-factor login. The member gets a mail first.
     */
    public function putRecoverAccount(AdminHeaders $headers, Request $request, string $orgId, string $memberId): EmptyResponse
    {
        $orgId = Uuid::parameter($request, $orgId);
        $memberId = Uuid::parameter($request, $memberId);
        $body = Body::json($request);
        $newMasterPasswordHash = $body->optionalString('newMasterPasswordHash');
        $key = $body->optionalString('key');
        $authentication = $body->optionalObject('authenticationData');
        $authentication = $authentication === null ? null : AuthenticationData::fromFields($authentication);
        $unlock = $body->optionalObject('unlockData');
        $unlock = $unlock === null ? null : UnlockData::fromFields($unlock);
        $resetMasterPassword = $body->defaultBool('resetMasterPassword');
        $resetTwoFactor = $body->defaultBool('resetTwoFactor');
        $orgId = $this->orgId($request, $orgId, $headers);

        $org = Organization::findByUuid($orgId) ?? throw ApiError::message('Required organization not found');
        $member = Membership::findByUuidAndOrg($memberId, $org->uuid) ?? throw ApiError::message("User to reset isn't member of required organization");
        $user = User::findByUuid($member->user_uuid) ?? throw ApiError::message('User not found');
        $this->checkResetPasswordApplicableAndPermissions($orgId, $memberId, $headers);

        if ($member->reset_password_key === null) {
            throw ApiError::message('Password reset not or not correctly enrolled');
        }
        if ($member->status !== Membership::STATUS_CONFIRMED) {
            throw ApiError::message('Organization user must be confirmed for password reset functionality');
        }

        $fallbackEmail = $resetTwoFactor && $this->config->mailEnabled() && $this->config->bool('email_2fa_auto_fallback') && $user->verified()
            && TwoFactor::findByUserAndType($user->uuid, TwoFactor::TYPE_EMAIL) === null;

        // Checked before the mail, so that a rejected request does not tell the user of a reset.
        $newPassword = null;
        if ($resetMasterPassword) {
            if ($authentication !== null && $unlock !== null) {
                $authentication->check($user, $unlock);
                if (! $authentication->kdf->matchesUser($user)) {
                    throw ApiError::message('KDF settings do not match the user account');
                }
                $newPassword = [$authentication->masterPasswordAuthenticationHash, $unlock->masterKeyWrappedUserKey];
            } elseif ($newMasterPasswordHash !== null && $key !== null) {
                $newPassword = [$newMasterPasswordHash, $key];
            } else {
                throw ApiError::message('Unprocessable request', 422, 'Missing fields to reset password');
            }
        }

        // The mail goes first: it proves the mail settings work and tells the user.
        try {
            Mail::sendAdminAccountRecovery($user->email, $user->displayName(), $org->name, $resetMasterPassword, $resetTwoFactor, $fallbackEmail);
        } catch (ApiError $error) {
            throw ApiError::message("Error sending user reset password email: {$error->debugText()}");
        }

        if ($newPassword !== null) {
            $user->setPassword($newPassword[0], $newPassword[1], true, null);
        }
        if ($resetTwoFactor) {
            TwoFactor::deleteAllByUser($user->uuid);
            Device::clearTwofactorRememberByUser($user->uuid);
            if (! $fallbackEmail || ! self::activatesEmail2fa($user->uuid)) {
                OrgPolicy::enforceTwoFactorForUser($user, $headers->user->uuid, $headers->device->atype, $headers->ip);
            }
        }
        $user->save();

        $this->nt->sendLogout($user, null);

        if ($resetMasterPassword) {
            self::logEvent(Event::ORGANIZATION_USER_ADMIN_RESET_PASSWORD, $memberId, $orgId, $headers);
        }
        if ($resetTwoFactor) {
            self::logEvent(Event::ORGANIZATION_USER_ADMIN_RESET_TWO_FACTOR, $memberId, $orgId, $headers);
        }

        return new EmptyResponse;
    }

    /**
     * GET /api/organizations/{org_id}/users/{member_id}/reset-password-details:
     * what an admin needs to set a new master password.
     */
    public function getResetPasswordDetails(AdminHeaders $headers, Request $request, string $orgId, string $memberId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $memberId = Uuid::parameter($request, $memberId);

        $org = Organization::findByUuid($orgId) ?? throw ApiError::message('Required organization not found');
        $member = Membership::findByUuidAndOrg($memberId, $orgId) ?? throw ApiError::message("User to reset isn't member of required organization");
        $user = User::findByUuid($member->user_uuid) ?? throw ApiError::message('User not found');
        $this->checkResetPasswordApplicableAndPermissions($orgId, $memberId, $headers);

        return Json::response(Json::sorted([
            'object' => 'organizationUserResetPasswordDetails',
            'organizationUserId' => $memberId,
            'kdf' => $user->client_kdf_type,
            'kdfIterations' => $user->client_kdf_iter,
            'kdfMemory' => $user->client_kdf_memory,
            'kdfParallelism' => $user->client_kdf_parallelism,
            'masterPasswordSalt' => $user->masterPasswordSalt(),
            'resetPasswordKey' => $member->reset_password_key,
            'encryptedPrivateKey' => $org->private_key,
        ]));
    }

    /**
     * PUT /api/organizations/{org_id}/users/{user_id}/reset-password-enrollment:
     * a member enrolls in account recovery with a key, or withdraws.
     */
    public function putResetPasswordEnrollment(OrgMemberHeaders $headers, Request $request, string $orgId, string $userId): EmptyResponse
    {
        $orgId = Uuid::parameter($request, $orgId);
        $userId = Uuid::parameter($request, $userId);
        $body = Body::json($request);
        $resetPasswordKey = $body->optionalString('resetPasswordKey');
        $masterPasswordHash = $body->optionalString('masterPasswordHash');
        $otp = $body->optionalString('otp');

        if ($userId !== $headers->user->uuid) {
            throw ApiError::message("User to enroll isn't member of required organization", logMessage: 'The user_id and acting user do not match');
        }
        $membership = $headers->membership;
        $this->checkResetPasswordApplicable($orgId);

        $resetPasswordKey = $resetPasswordKey === '' ? null : $resetPasswordKey;
        if ($resetPasswordKey === null && $this->orgIsResetPasswordAutoEnroll($orgId)) {
            throw ApiError::message("Reset password can't be withdrawn due to an enterprise policy");
        }
        if ($resetPasswordKey !== null) {
            (new PasswordOrOtpData($masterPasswordHash, $otp))->validate($headers->user, true, $this->config);
        }

        $membership->reset_password_key = $resetPasswordKey;
        $membership->save();
        self::logEvent($resetPasswordKey !== null ? Event::ORGANIZATION_USER_RESET_PASSWORD_ENROLL : Event::ORGANIZATION_USER_RESET_PASSWORD_WITHDRAW,
            $membership->uuid, $orgId, $headers);

        return new EmptyResponse;
    }

    /**
     * POST /api/ciphers/import-organization?organizationId=: ciphers into
     * existing or new collections. Ciphers that fail are skipped silently.
     */
    public function postOrgImport(OrgMemberHeaders $headers, Request $request): EmptyResponse
    {
        $orgId = Query::first($request, 'organizationId') ?? throw new HttpStatus(422, 'No organizationId.');
        $body = Body::json($request);
        $ciphers = array_map(CipherData::fromFields(...), $body->objectList('ciphers'));
        $collections = array_map(static fn (Fields $collection): array => [
            'name' => $collection->string('name'),
            'id' => $collection->optionalString('id'),
            'externalId' => $collection->optionalString('externalId'),
        ], $body->objectList('collections'));
        $relations = array_map(
            static fn (Fields $relation): array => [$relation->unsigned('key'), $relation->unsigned('value')],
            $body->objectList('collectionRelationships'),
        );

        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Organization not found', logMessage: "Organization id's do not match");
        }
        // The guard lets invited and accepted members through too.
        if ($headers->membership->status !== Membership::STATUS_CONFIRMED) {
            throw ApiError::message('You need to be a Member of the Organization to call this endpoint');
        }

        // Nothing is imported if one item is invalid.
        $ciphersController = app(CiphersController::class);
        $ciphersController->validateCipherData($ciphers);

        $existing = [];
        foreach (OrgCollection::findByOrganization($orgId) as $collection) {
            $existing[$collection->uuid] = $collection;
        }
        $collectionIds = [];
        foreach ($collections as $data) {
            $collection = $data['id'] === null ? null : ($existing[$data['id']] ?? null);
            if ($collection !== null) {
                if ($headers->membership->typeBelow(Membership::TYPE_ADMIN) && ! $collection->isWritableByUser($headers->membership->user_uuid)) {
                    throw ApiError::compact("The current user isn't allowed to manage this collection");
                }
            } else {
                // Only members who manage all collections may create new ones.
                if ($headers->membership->typeBelow(Membership::TYPE_ADMIN) && ! $headers->membership->hasFullAccess()) {
                    throw ApiError::compact("The current user isn't allowed to create new collections");
                }
                $collection = OrgCollection::new($orgId, $data['name'], $data['externalId']);
                $collection->save();
            }
            $collectionIds[] = $collection->uuid;
        }

        $userHeaders = new Headers($headers->host, $headers->device, $headers->user, $headers->ip);
        $cipherIds = [];
        foreach ($ciphers as $data) {
            $data->folderId = null;
            // The organization of the request, whatever the client claims.
            $data->organizationId = $orgId;
            $cipher = Cipher::new($data->type, $data->name);
            try {
                $ciphersController->updateCipherFromData($cipher, $data, $userHeaders, UpdateType::None, $collectionIds);
            } catch (ApiError) {
                // Upstream ignores the cipher's errors, but still relates its id below.
            }
            $cipherIds[] = $cipher->uuid;
        }

        foreach ($relations as [$cipherIndex, $collectionIndex]) {
            if (! isset($cipherIds[$cipherIndex], $collectionIds[$collectionIndex])) {
                throw ApiError::compact('Invalid collection relationship');
            }
            CollectionCipher::save($cipherIds[$cipherIndex], $collectionIds[$collectionIndex]);
        }

        $headers->user->updateRevision();

        return new EmptyResponse;
    }

    /**
     * GET /api/organizations/{org_id}/export: all collections and ciphers,
     * for owners and admins; exporting only managed collections is not supported.
     */
    public function getOrgExport(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);

        $collections = OrgCollection::findByOrganization($orgId)->map(static fn (OrgCollection $collection): array => $collection->toApi())->all();
        $sync = CiphersController::syncData($headers->user->uuid, organizationView: true);
        $ciphers = Cipher::findByOrg($orgId)->map(static fn (Cipher $cipher): array => $cipher->toApi($headers->host, $headers->user->uuid, $sync, organizationView: true))->all();

        // Clients cannot read keys with an upper-case first letter.
        return Json::response(Json::sorted([
            'collections' => JsonValue::lowercaseFirstKeys(array_values($collections)),
            'ciphers' => JsonValue::lowercaseFirstKeys(array_values($ciphers)),
        ]));
    }

    /**
     * POST /api/organizations/{org_id}/api-key: the organization's key for
     * the directory connector, made on first request.
     */
    public function postApiKey(OwnerHeaders $headers, Request $request, string $orgId): Response
    {
        return $this->apiKey($headers, $request, $orgId, false);
    }

    /**
     * POST /api/organizations/{org_id}/rotate-api-key
     */
    public function rotateApiKey(OwnerHeaders $headers, Request $request, string $orgId): Response
    {
        return $this->apiKey($headers, $request, $orgId, true);
    }

    /**
     * GET /api/organizations/{org_id}/groups: for members with full access,
     * also through a group, or who manage a collection, to assign groups.
     */
    public function getGroups(ManagerHeadersLoose $headers, Request $request, string $orgId): Response
    {
        return $this->groupsData(false, $headers, $request, $orgId);
    }

    /**
     * GET /api/organizations/{org_id}/groups/details: with the groups'
     * collections, for members with full access only.
     */
    public function getGroupsDetails(ManagerHeadersLoose $headers, Request $request, string $orgId): Response
    {
        return $this->groupsData(true, $headers, $request, $orgId);
    }

    /**
     * POST /api/organizations/{org_id}/groups
     */
    public function postGroups(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $data = self::groupRequest(Body::json($request));
        $this->checkGroups($orgId, $headers);
        self::validateGroupRequest($orgId, $data);

        $group = Group::new($orgId, $data['name'], $data['accessAll'], $data['externalId']);
        self::logEvent(Event::GROUP_CREATED, $group->uuid, $orgId, $headers);

        return Json::response(self::addUpdateGroup($group, $data, $orgId, $headers));
    }

    /**
     * PUT /api/organizations/{org_id}/groups/{group_id}: the external id stays,
     * only the directory import sets it.
     */
    public function putGroup(AdminHeaders $headers, Request $request, string $orgId, string $groupId): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $groupId = Uuid::parameter($request, $groupId);
        $data = self::groupRequest(Body::json($request));
        $this->checkGroups($orgId, $headers);

        $group = self::findGroup($groupId, $orgId);
        self::validateGroupRequest($orgId, $data);
        $group->name = $data['name'];
        $group->access_all = $data['accessAll'];

        CollectionGroup::deleteAllByGroup($groupId, $orgId);
        GroupUser::deleteAllByGroup($groupId, $orgId);
        self::logEvent(Event::GROUP_UPDATED, $group->uuid, $orgId, $headers);

        return Json::response(self::addUpdateGroup($group, $data, $orgId, $headers));
    }

    /**
     * GET /api/organizations/{org_id}/groups/{group_id}/details
     */
    public function getGroupDetails(AdminHeaders $headers, Request $request, string $orgId, string $groupId): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $groupId = Uuid::parameter($request, $groupId);
        $this->checkGroups($orgId, $headers);

        return Json::response(self::findGroup($groupId, $orgId)->toApiDetails());
    }

    /**
     * DELETE /api/organizations/{org_id}/groups/{group_id}
     */
    public function deleteGroup(AdminHeaders $headers, Request $request, string $orgId, string $groupId): EmptyResponse
    {
        $orgId = Uuid::parameter($request, $orgId);
        $this->deleteGroupImpl($orgId, Uuid::parameter($request, $groupId), $headers);

        return new EmptyResponse;
    }

    /**
     * DELETE /api/organizations/{org_id}/groups: one after the other, until one fails.
     */
    public function bulkDeleteGroups(AdminHeaders $headers, Request $request, string $orgId): EmptyResponse
    {
        $orgId = Uuid::parameter($request, $orgId);
        $ids = Body::json($request)->stringList('ids');
        $this->checkGroups($orgId, $headers);

        foreach ($ids as $groupId) {
            $this->deleteGroupImpl($orgId, $groupId, $headers);
        }

        return new EmptyResponse;
    }

    /**
     * GET /api/organizations/{org_id}/groups/{group_id}
     */
    public function getGroup(AdminHeaders $headers, Request $request, string $orgId, string $groupId): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $groupId = Uuid::parameter($request, $groupId);
        $this->checkGroups($orgId, $headers);

        return Json::response(self::findGroup($groupId, $orgId)->toApi());
    }

    /**
     * GET /api/organizations/{org_id}/groups/{group_id}/users: the ids of its memberships.
     */
    public function getGroupMembers(AdminHeaders $headers, Request $request, string $orgId, string $groupId): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $groupId = Uuid::parameter($request, $groupId);
        $this->checkGroups($orgId, $headers);

        Group::findByUuidAndOrg($groupId, $orgId)
            ?? throw ApiError::message('Group could not be found!', logMessage: 'Group uuid is invalid or does not belong to the organization');

        return Json::response(array_map(static fn (GroupUser $groupUser): string => $groupUser->membershipUuid, GroupUser::findByGroup($groupId, $orgId)));
    }

    /**
     * GET /api/organizations/{org_id}/policies
     */
    public function listPolicies(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $policies = OrgPolicy::findByOrg($orgId)->map(static fn (OrgPolicy $policy): array => $policy->toApi())->all();

        return Json::response(Json::sorted(['data' => array_values($policies), 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * GET /api/organizations/{org_id}/policies/token?token=: for the invited,
     * who have no account yet; the invitation token is the authorization.
     */
    public function listPoliciesToken(Request $request, string $orgId): Response
    {
        $token = Query::first($request, 'token');
        if (! Uuid::isValid($orgId) || $token === null) {
            // The route does not match. get_policy is next: its guard comes first, then it cannot read "token" as a type.
            app(AdminHeaders::class);

            throw new HttpStatus(404, 'No token or no valid organization id.');
        }

        $claims = $this->jwt->decode($token, JwtIssuer::Invite, fields: Jwt::INVITE_CLAIMS);
        if ($claims['org_id'] !== $orgId) {
            throw ApiError::message("Token doesn't match request organization");
        }

        // Invited through the admin panel.
        if ($orgId === self::FAKE_ADMIN_UUID) {
            return Json::response(new stdClass);
        }

        $policies = OrgPolicy::findByOrg($orgId)->map(static fn (OrgPolicy $policy): array => $policy->toApi())->all();

        return Json::response(Json::sorted(['data' => array_values($policies), 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * GET /api/plans: just enough for the clients to create an organization.
     */
    public function getPlans(): Response
    {
        $free = static fn (int $product): array => ['object' => 'plan', 'type' => 0, 'product' => $product, 'name' => 'Free',
            'nameLocalizationKey' => 'planNameFree', 'bitwardenProduct' => $product, 'maxUsers' => 0, 'descriptionLocalizationKey' => 'planDescFree'];

        return Json::response(Json::sorted(['object' => 'list', 'data' => [$free(0), $free(1)], 'continuationToken' => null]));
    }

    /**
     * GET /api/organizations/{org_id}/billing/vnext/warnings: there is no billing to warn about.
     */
    public function getBillingWarnings(OrgMemberHeaders $headers, Request $request, string $orgId): Response
    {
        Uuid::parameter($request, $orgId);

        return Json::response(Json::sorted(['freeTrial' => null, 'inactiveSubscription' => null, 'resellerRenewal' => null, 'taxId' => null]));
    }

    /**
     * GET /api/organizations/{org_id}/billing/vnext/self-host/metadata: no
     * Secrets Manager and no seat count, but no 404 the web vault trips on.
     */
    public function getSelfHostBillingMetadata(OrgMemberHeaders $headers, Request $request, string $orgId): Response
    {
        Uuid::parameter($request, $orgId);

        return Json::response(Json::sorted(['isOnSecretsManagerStandalone' => false, 'organizationOccupiedSeats' => 0]));
    }

    /**
     * POST /api/organizations/domain/sso/verified: the clients prefill the
     * organization identifier of an SSO login with it; there is a single SSO
     * integration, so a dummy, whether SSO is enabled or not.
     */
    public function getOrgDomainSsoVerified(): Response
    {
        return Json::response(Json::sorted(['object' => 'list', 'data' => [[
            'organizationIdentifier' => self::FAKE_SSO_IDENTIFIER,
            'organizationName' => self::FAKE_SSO_IDENTIFIER,
            'domainName' => $this->config->string('domain'),
        ]], 'continuationToken' => null]));
    }

    /**
     * GET /api/organizations/{identifier}/auto-enroll-status: during the SSO
     * enrollment, whether account recovery enrolls the user. The fake SSO
     * organization stands for the user's main organization.
     */
    public function getAutoEnrollStatus(Headers $headers, string $identifier): Response
    {
        if ($identifier === self::FAKE_SSO_IDENTIFIER) {
            $member = Membership::findMainUserOrg($headers->user->uuid);
            $org = $member === null ? null : Organization::findByUuid($member->org_uuid);
        } else {
            $org = Organization::findByUuid($identifier);
        }

        return Json::response(Json::sorted($org === null
            ? ['id' => $identifier, 'identifier' => $identifier, 'resetPasswordEnabled' => false]
            : ['id' => $org->uuid, 'identifier' => $org->uuid, 'resetPasswordEnabled' => $this->orgIsResetPasswordAutoEnroll($org->uuid)]));
    }

    /**
     * GET /api/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password:
     * the SSO enrollment asks with this fake organization id.
     */
    public function getDummyMasterPasswordPolicy(): Response
    {
        return Json::response($this->defaultMasterPasswordPolicy(self::FAKE_SSO_IDENTIFIER)->toApi());
    }

    /**
     * GET /api/organizations/{org_id}/policies/master-password: the
     * organization's, or the one SSO configures.
     */
    public function getMasterPasswordPolicy(OrgMemberHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $policy = OrgPolicy::findByOrgAndType($orgId, OrgPolicy::TYPE_MASTER_PASSWORD) ?? $this->defaultMasterPasswordPolicy($orgId);

        return Json::response($policy->toApi());
    }

    /**
     * GET /api/organizations/{org_id}/policies/{pol_type}: a disabled one when there is none.
     */
    public function getPolicy(AdminHeaders $headers, Request $request, string $orgId, string $polType): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $type = self::i32Parameter($request, $polType);
        $orgId = $this->orgId($request, $orgId, $headers);
        if (! in_array($type, OrgPolicy::TYPES, true)) {
            throw ApiError::message('Invalid or unsupported policy type');
        }

        $policy = OrgPolicy::findByOrgAndType($orgId, $type) ?? OrgPolicy::new($orgId, $type, false, 'null');

        return Json::response($policy->toApi());
    }

    /**
     * PUT /api/organizations/{org_id}/policies/{pol_type}: enabling the 2FA
     * and single organization policies revokes the members they now exclude.
     */
    public function putPolicy(AdminHeaders $headers, Request $request, string $orgId, string $polType): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $type = self::i32Parameter($request, $polType);
        $policyData = Body::json($request)->object('policy');
        $enabled = $policyData->bool('enabled');
        $data = $policyData->value('data');
        $orgId = $this->orgId($request, $orgId, $headers);

        if (! in_array($type, OrgPolicy::TYPES, true)) {
            throw ApiError::message('Invalid or unsupported policy type');
        }

        $current = OrgPolicy::findByOrgAndType($orgId, $type);
        $currentlyEnabled = $current?->enabled === true;

        // Fill Assist depends on Single Organization, checked like Bitwarden only when a policy changes state.
        if ($type === OrgPolicy::TYPE_FILL_ASSIST && $enabled && ! $currentlyEnabled
            && OrgPolicy::findByOrgAndType($orgId, OrgPolicy::TYPE_SINGLE_ORG)?->enabled !== true) {
            throw ApiError::message('Turn on the Single organization policy because it is required for the Activate fill assist policy.');
        }
        if ($type === OrgPolicy::TYPE_SINGLE_ORG && ! $enabled && $currentlyEnabled
            && OrgPolicy::findByOrgAndType($orgId, OrgPolicy::TYPE_FILL_ASSIST)?->enabled === true) {
            throw ApiError::message('Turn off the Activate fill assist policy because it requires the Single organization policy.');
        }

        // Bitwarden requires the single organization policy for account recovery; here only when configured.
        if ($this->config->bool('enforce_single_org_with_reset_pw_policy')) {
            if ($type === OrgPolicy::TYPE_RESET_PASSWORD && $enabled
                && OrgPolicy::findByOrgAndType($orgId, OrgPolicy::TYPE_SINGLE_ORG)?->enabled !== true) {
                throw ApiError::message('Single Organization policy is not enabled. It is mandatory for this policy to be enabled.');
            }
            if ($type === OrgPolicy::TYPE_SINGLE_ORG && ! $enabled
                && OrgPolicy::findByOrgAndType($orgId, OrgPolicy::TYPE_RESET_PASSWORD)?->enabled === true) {
                throw ApiError::message('Account recovery policy is enabled. It is not allowed to disable this policy.');
            }
        }

        if ($type === OrgPolicy::TYPE_FILL_ASSIST) {
            self::checkFillAssistData($data, $enabled);
        }

        if ($type === OrgPolicy::TYPE_TWO_FACTOR_AUTHENTICATION && $enabled) {
            OrgPolicy::enforceTwoFactorForOrg($orgId, $headers->user->uuid, $headers->device->atype, $headers->ip);
        }

        if ($type === OrgPolicy::TYPE_SINGLE_ORG && $enabled) {
            foreach (Membership::findByOrg($orgId) as $member) {
                // Members below admin who joined; invited and revoked ones are checked when they try again.
                if ($member->typeBelow(Membership::TYPE_ADMIN) && $member->status !== Membership::STATUS_INVITED
                    && Membership::countAcceptedAndConfirmedByUser($member->user_uuid, $member->org_uuid) > 0) {
                    if ($this->config->mailEnabled()) {
                        $org = Organization::findByUuid($member->org_uuid) ?? throw new \LogicException("Organization {$member->org_uuid} is missing");
                        $user = User::findByUuid($member->user_uuid) ?? throw new \LogicException("User {$member->user_uuid} is missing");
                        Mail::sendSingleOrgRemovedFromOrg($user->email, $org->name);
                    }
                    self::logEvent(Event::ORGANIZATION_USER_REVOKED_SINGLE_ORGANIZATION_NON_COMPLIANCE, $member->uuid, $orgId, $headers);
                    $member->revoke();
                    $member->save();
                }
            }
        }

        $policy = $current ?? OrgPolicy::new($orgId, $type, false, '{}');
        $policy->enabled = $enabled;
        // serde_json::to_string of an Option<Value>: keys sorted, none as null.
        $policy->data = Json::encode(Json::sorted($data));
        $policy->save();
        self::logEvent(Event::POLICY_UPDATED, $policy->uuid, $orgId, $headers);

        return Json::response($policy->toApi());
    }

    /**
     * The data of a Fill Assist policy (FillAssistPolicyData): a rules URL,
     * which an enabled policy needs, with HTTPS.
     *
     * @throws ApiError
     */
    private static function checkFillAssistData(mixed $data, bool $enabled): void
    {
        $rulesUrl = self::fillAssistRulesUrl($data) ?? throw ApiError::message('Invalid data for FillAssist policy: rulesUrl has an invalid value.');
        if (! $enabled) {
            return;
        }

        // Blank after str::trim.
        if ($rulesUrl[0] === null || preg_match('/^\p{White_Space}*$/Du', $rulesUrl[0]) === 1) {
            throw ApiError::message('The RulesUrl field is required.');
        }
        $url = Url::parse($rulesUrl[0]);
        if ($url === null || ($url->getAsciiHost() ?? '') === '' || ! in_array($url->getScheme(), ['http', 'https', 'ftp'], true)) {
            throw ApiError::message('The RulesUrl field is not a valid fully-qualified http, https, or ftp URL.');
        }
        if ($url->getScheme() !== 'https') {
            throw ApiError::message('RulesUrl must use HTTPS.');
        }
    }

    /**
     * serde_json::from_value::<FillAssistPolicyData>: null is no data, an
     * object has rulesUrl (alias RulesUrl), and like any derived struct, a
     * sequence holds its one field. Null when it does not deserialize.
     *
     * @return array{?string}|null
     */
    private static function fillAssistRulesUrl(mixed $data): ?array
    {
        if ($data === null) {
            return [null];
        }
        if ($data instanceof stdClass) {
            $values = array_values(array_intersect_key(get_object_vars($data), ['rulesUrl' => true, 'RulesUrl' => true]));
        } elseif (is_array($data) && count($data) === 1) {
            $values = $data;
        } else {
            return null;
        }
        $value = $values[0] ?? null;

        return count($values) <= 1 && ($value === null || is_string($value)) ? [$value] : null;
    }

    /**
     * get_groups_data
     *
     * @throws ApiError|HttpStatus
     */
    private function groupsData(bool $details, ManagerHeadersLoose $headers, Request $request, string $orgId): Response
    {
        $orgId = $this->orgId($request, $orgId, $headers);
        $member = $headers->membership;

        $fullAccess = $member->hasFullAccess() || (Group::enabled() && GroupUser::hasFullAccessByMember($orgId, $member->uuid));
        $allowed = $details ? $fullAccess : $fullAccess || OrgCollection::hasManageableCollectionByUser($orgId, $member->user_uuid);
        if (! $allowed) {
            throw ApiError::message('Resource not found.', 404, 'User does not have access');
        }

        // Clients ask regardless of whether groups are enabled.
        $groups = Group::enabled()
            ? array_values(Group::findByOrganization($orgId)->map(static fn (Group $group): array => $details ? $group->toApiDetails() : $group->toApi())->all())
            : [];

        return Json::response(Json::sorted(['data' => $groups, 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * The owner confirms with password or OTP; saving failures panic upstream.
     *
     * @throws ApiError|HttpStatus
     */
    private function apiKey(OwnerHeaders $headers, Request $request, string $orgId, bool $rotate): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $data = PasswordOrOtpData::fromFields(Body::json($request));
        $orgId = $this->orgId($request, $orgId, $headers);
        $data->validate($headers->user, true, $this->config);

        $apiKey = OrganizationApiKey::findByOrgUuid($orgId);
        try {
            if ($apiKey === null) {
                $apiKey = OrganizationApiKey::new($orgId, OrganizationApiKey::generate());
                $apiKey->save();
            } elseif ($rotate) {
                $apiKey->api_key = OrganizationApiKey::generate();
                $apiKey->revision_date = Dates::now();
                $apiKey->save();
            }
        } catch (ApiError $error) {
            throw new \LogicException($rotate ? 'Error rotating organization API Key' : 'Error creating organization API Key', previous: $error);
        }

        return Json::response(Json::sorted(['apiKey' => $apiKey->api_key, 'revisionDate' => Dates::format($apiKey->revision_date), 'object' => 'apiKey']));
    }

    /**
     * The email method instead of the removed ones; false when that fails.
     */
    private static function activatesEmail2fa(string $userUuid): bool
    {
        try {
            EmailController::findAndActivateEmail2fa($userUuid);

            return true;
        } catch (ApiError) {
            return false;
        }
    }

    /**
     * core::accept_org_invite: accepted, if the policies allow it; whoever
     * invited the member hears of it.
     *
     * @throws ApiError
     */
    public static function acceptOrgInvite(User $user, Membership $member, ?string $resetPasswordKey): void
    {
        if ($member->status !== Membership::STATUS_INVITED) {
            throw ApiError::message('User already accepted the invitation');
        }
        $member->status = Membership::STATUS_ACCEPTED;
        $member->reset_password_key = $resetPasswordKey;
        OrgPolicy::checkUserAllowed($member, 'join');
        $member->save();

        if (app(Config::class)->mailEnabled()) {
            $org = Organization::findByUuid($member->org_uuid) ?? throw ApiError::message('Organization not found.');
            // The member must be confirmed by hand now.
            Mail::sendInviteAccepted($user->email, $member->invited_by_email ?? $org->billing_email, $org->name);
        }
    }

    /**
     * Account recovery needs mail and the enabled policy; admins may only
     * recover members up to admins, owners anyone.
     *
     * @throws ApiError
     */
    private function checkResetPasswordApplicableAndPermissions(string $orgId, string $memberId, AdminHeaders $headers): void
    {
        $this->checkResetPasswordApplicable($orgId);

        $target = Membership::findByUuidAndOrg($memberId, $orgId) ?? throw ApiError::message('Reset target user not found');
        $allowed = match ($headers->membership->atype) {
            Membership::TYPE_OWNER => true,
            Membership::TYPE_ADMIN => $target->typeBelow(Membership::TYPE_OWNER),
            default => false,
        };
        if (! $allowed) {
            throw ApiError::message("No permission to reset this user's password");
        }
    }

    /**
     * @throws ApiError
     */
    private function checkResetPasswordApplicable(string $orgId): void
    {
        if (! $this->config->mailEnabled()) {
            throw ApiError::message('Password reset is not supported on an email-disabled instance.');
        }
        $policy = OrgPolicy::findByOrgAndType($orgId, OrgPolicy::TYPE_RESET_PASSWORD) ?? throw ApiError::message('Policy not found');
        if (! $policy->enabled) {
            throw ApiError::message('Reset password policy not enabled');
        }
    }

    /**
     * OrgPolicy::org_is_reset_password_auto_enroll: inactive without mail.
     */
    private function orgIsResetPasswordAutoEnroll(string $orgId): bool
    {
        if (! $this->config->mailEnabled()) {
            return false;
        }
        $policy = OrgPolicy::findByOrgAndType($orgId, OrgPolicy::TYPE_RESET_PASSWORD);
        if ($policy === null) {
            return false;
        }

        // ResetPasswordDataModel { autoEnrollEnabled (alias AutoEnrollEnabled): bool }
        [$ok, $data] = JsonValue::decode($policy->data);
        $values = $ok && $data instanceof stdClass ? array_values(array_intersect_key(get_object_vars($data), ['autoEnrollEnabled' => true, 'AutoEnrollEnabled' => true])) : [];
        if (count($values) !== 1 || ! is_bool($values[0])) {
            logger()->error("Failed to deserialize ResetPasswordDataModel: {$policy->data}");

            return false;
        }

        return $policy->enabled && $values[0];
    }

    /**
     * The master password policy SSO_MASTER_PASSWORD_POLICY sets while SSO is
     * enabled; a disabled one otherwise.
     */
    private function defaultMasterPasswordPolicy(string $orgId): OrgPolicy
    {
        $configured = $this->config->optionalString('sso_master_password_policy');
        [$ok, $value] = $configured === null ? [false, null] : JsonValue::decode($configured);
        if ($ok && $value instanceof stdClass && $this->config->bool('sso_enabled')) {
            return OrgPolicy::new($orgId, OrgPolicy::TYPE_MASTER_PASSWORD, true, Json::encode(Json::sorted($value)));
        }

        return OrgPolicy::new($orgId, OrgPolicy::TYPE_MASTER_PASSWORD, false, 'null');
    }

    /**
     * An i32 path parameter, as Rust parses it; a bad one forwards like a bad UUID.
     *
     * @throws HttpStatus
     */
    private static function i32Parameter(Request $request, string $value): int
    {
        return CheckedInt::parseI32($value)
            ?? throw new HttpStatus(in_array($request->getMethod(), ['GET', 'HEAD'], true) ? 404 : 422, 'Path parameter is not an i32.');
    }

    /**
     * The checks every group route of admins starts with.
     *
     * @throws ApiError
     */
    private function checkGroups(string $orgId, AdminHeaders $headers): void
    {
        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Organization not found', logMessage: "Organization id's do not match");
        }
        if (! Group::enabled()) {
            throw ApiError::message('Group support is disabled');
        }
    }

    /**
     * @throws ApiError
     */
    private function deleteGroupImpl(string $orgId, string $groupId, AdminHeaders $headers): void
    {
        $this->checkGroups($orgId, $headers);
        $group = self::findGroup($groupId, $orgId);
        self::logEvent(Event::GROUP_DELETED, $group->uuid, $orgId, $headers);
        $group->deleteGroup($orgId);
    }

    /**
     * @throws ApiError
     */
    private static function findGroup(string $groupId, string $orgId): Group
    {
        return Group::findByUuidAndOrg($groupId, $orgId)
            ?? throw ApiError::message('Group not found', logMessage: 'Group uuid is invalid or does not belong to the organization');
    }

    /**
     * GroupRequest
     *
     * @return array{name: string, accessAll: bool, externalId: ?string, collections: list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>, users: list<string>}
     *
     * @throws HttpStatus
     */
    private static function groupRequest(Fields $body): array
    {
        return [
            'name' => $body->string('name'),
            'accessAll' => $body->defaultBool('accessAll'),
            'externalId' => $body->optionalString('externalId'),
            'collections' => array_map(self::collectionAccessData(...), $body->objectList('collections')),
            'users' => $body->stringList('users'),
        ];
    }

    /**
     * GroupRequest::validate: the collections and members must be the organization's.
     *
     * @param  array{collections: list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>, users: list<string>}  $data
     *
     * @throws ApiError
     */
    private static function validateGroupRequest(string $orgId, array $data): void
    {
        $collections = OrgCollection::findByOrganization($orgId)->pluck('uuid')->all();
        foreach ($data['collections'] as $collection) {
            if (! in_array($collection['id'], $collections, true)) {
                throw ApiError::message('Invalid collection', logMessage: 'Collection '.EscapeDebug::of($collection['id'])." does not belong to organization {$orgId}!");
            }
        }

        $members = Membership::findByOrg($orgId)->pluck('uuid')->all();
        foreach ($data['users'] as $memberId) {
            if (! in_array($memberId, $members, true)) {
                throw ApiError::message('Invalid member', logMessage: 'Member '.EscapeDebug::of($memberId)." does not belong to organization {$orgId}!");
            }
        }
    }

    /**
     * add_update_group: saves the group with its collections and members.
     *
     * @param  array{collections: list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>, users: list<string>}  $data
     * @return array<string, mixed>
     *
     * @throws ApiError
     */
    private static function addUpdateGroup(Group $group, array $data, string $orgId, AdminHeaders $headers): array
    {
        $group->save();

        foreach ($data['collections'] as $collection) {
            (new CollectionGroup($collection['id'], $group->uuid, $collection['readOnly'], $collection['hidePasswords'], $collection['manage']))->save($orgId);
        }
        foreach ($data['users'] as $memberId) {
            (new GroupUser($group->uuid, $memberId))->save();
            self::logEvent(Event::ORGANIZATION_USER_UPDATED_GROUPS, $memberId, $orgId, $headers);
        }

        return $group->toApi();
    }

    /**
     * api::core::events::log_event by the member of the request.
     */
    private static function logEvent(int $type, string $sourceUuid, string $orgId, OrgHeaders $headers): void
    {
        Event::log($type, $sourceUuid, $orgId, $headers->user->uuid, $headers->device->atype, $headers->ip);
    }

    /**
     * The org id of the path must be the guard's; it is, as the guard read it from there.
     *
     * @throws ApiError|HttpStatus
     */
    private function orgId(Request $request, string $orgId, OrgHeaders $headers): string
    {
        $orgId = Uuid::parameter($request, $orgId);
        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Organization not found', logMessage: "Organization id's do not match");
        }

        return $orgId;
    }

    /**
     * @throws ApiError
     */
    private function deleteCollection(string $orgId, string $collectionId, OrgHeaders $headers): void
    {
        $collection = OrgCollection::findByUuidAndOrg($collectionId, $orgId)
            ?? throw ApiError::message('Collection not found', logMessage: 'Collection does not exist or does not belong to this organization');
        self::logEvent(Event::COLLECTION_DELETED, $collection->uuid, $orgId, $headers);
        $collection->deleteCollection();
    }

    /**
     * organizations::reinvite_member_impl: the invitation goes out again by
     * mail; without mail, users with an account accept right away.
     *
     * @throws ApiError
     */
    private function reinvite(string $orgId, string $memberId, string $invitedByEmail): void
    {
        $member = Membership::findByUuidAndOrg($memberId, $orgId) ?? throw ApiError::message("The user hasn't been invited to the organization.");
        if ($member->status !== Membership::STATUS_INVITED) {
            throw ApiError::message('The user is already accepted or confirmed to the organization');
        }
        $user = User::findByUuid($member->user_uuid) ?? throw ApiError::message('User not found.');
        if (! $this->config->bool('invitations_allowed') && $user->password_hash === '') {
            throw ApiError::message('Invitations are not allowed.');
        }
        $org = Organization::findByUuid($orgId) ?? throw ApiError::message('Error looking up organization.');

        if ($this->config->mailEnabled()) {
            Mail::sendInvite($user, $orgId, $member->uuid, $org->name, $invitedByEmail);
        } elseif ($user->password_hash === '') {
            Invitation::new($user->email)->save();
        } else {
            Invitation::take($user->email);
            $member->status = Membership::STATUS_ACCEPTED;
            $member->save();
        }
    }

    /**
     * organizations::confirm_invite_impl: the member gets the organization key.
     *
     * @throws ApiError
     */
    private function confirm(string $orgId, string $memberId, string $key, AdminHeaders $headers): void
    {
        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Organization not found', logMessage: "Organization id's do not match");
        }
        if ($key === '' || $memberId === '') {
            throw ApiError::message('Key or UserId is not set, unable to process request');
        }

        $member = Membership::findByUuidAndOrg($memberId, $orgId) ?? throw ApiError::message("The specified user isn't a member of the organization");
        if ($member->atype !== Membership::TYPE_USER && $headers->membership->atype !== Membership::TYPE_OWNER) {
            throw ApiError::message('Only Owners can confirm Managers, Admins or Owners');
        }
        if ($member->status !== Membership::STATUS_ACCEPTED) {
            throw ApiError::message('User in invalid state');
        }

        $member->status = Membership::STATUS_CONFIRMED;
        $member->akey = $key;
        OrgPolicy::checkUserAllowed($member, 'confirm');
        self::logEvent(Event::ORGANIZATION_USER_CONFIRMED, $member->uuid, $orgId, $headers);

        if ($this->config->mailEnabled()) {
            $org = Organization::findByUuid($orgId) ?? throw ApiError::message('Error looking up organization.');
            $user = User::findByUuid($member->user_uuid) ?? throw ApiError::message('Error looking up user.');
            Mail::sendInviteConfirmed($user->email, $org->name);
        }

        try {
            $member->save();
        } finally {
            $user = User::findByUuid($member->user_uuid);
            if ($user !== null) {
                $this->nt->sendUserUpdate(UpdateType::SyncOrgKeys, $user, $headers->device->push_uuid);
            }
        }
    }

    /**
     * organizations::delete_member_impl
     *
     * @throws ApiError
     */
    private function removeMember(string $orgId, string $memberId, AdminHeaders $headers): void
    {
        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Organization not found', logMessage: "Organization id's do not match");
        }
        $member = Membership::findByUuidAndOrg($memberId, $orgId) ?? throw ApiError::message("User to delete isn't member of the organization");
        if ($member->atype !== Membership::TYPE_USER && $headers->membership->atype !== Membership::TYPE_OWNER) {
            throw ApiError::message('Only Owners can delete Admins or Owners');
        }
        if ($member->atype === Membership::TYPE_OWNER && $member->status === Membership::STATUS_CONFIRMED
            && Membership::countConfirmedByOrgAndType($orgId, Membership::TYPE_OWNER) <= 1) {
            throw ApiError::message("Can't delete the last owner");
        }

        self::logEvent(Event::ORGANIZATION_USER_REMOVED, $member->uuid, $orgId, $headers);
        $user = User::findByUuid($member->user_uuid);
        if ($user !== null) {
            $this->nt->sendUserUpdate(UpdateType::SyncOrgKeys, $user, $headers->device->push_uuid);
        }
        // Without mail the invitation goes with the last pending membership.
        if ($user !== null && ! $this->config->mailEnabled()
            && ! Membership::findInvitedByUser($user->uuid)->contains(static fn (Membership $other): bool => $other->uuid !== $member->uuid)) {
            Invitation::take($user->email);
        }

        $member->deleteMembership();
    }

    /**
     * organizations::revoke_member_impl
     *
     * @throws ApiError
     */
    private function revoke(string $orgId, string $memberId, AdminHeaders $headers): void
    {
        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Organization not found', logMessage: "Organization id's do not match");
        }
        $member = Membership::findByUuidAndOrg($memberId, $orgId) ?? throw ApiError::message('User not found in organization');
        if ($member->status <= Membership::STATUS_REVOKED) {
            throw ApiError::message('User is already revoked');
        }
        if ($member->user_uuid === $headers->user->uuid) {
            throw ApiError::message('You cannot revoke yourself');
        }
        if ($member->atype === Membership::TYPE_OWNER && $headers->membership->atype !== Membership::TYPE_OWNER) {
            throw ApiError::message('Only owners can revoke other owners');
        }
        if ($member->atype === Membership::TYPE_OWNER && Membership::countConfirmedByOrgAndType($orgId, Membership::TYPE_OWNER) <= 1) {
            throw ApiError::message('Organization must have at least one confirmed owner');
        }

        $member->revoke();
        $member->save();
        self::logEvent(Event::ORGANIZATION_USER_REVOKED, $member->uuid, $orgId, $headers);
    }

    /**
     * organizations::restore_member_impl. Invited members count as active.
     *
     * @throws ApiError
     */
    private function restore(string $orgId, string $memberId, AdminHeaders $headers): void
    {
        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Organization not found', logMessage: "Organization id's do not match");
        }
        $member = Membership::findByUuidAndOrg($memberId, $orgId) ?? throw ApiError::message('User not found in organization');
        if ($member->status >= Membership::STATUS_ACCEPTED) {
            throw ApiError::message('User is already active');
        }
        if ($member->user_uuid === $headers->user->uuid) {
            throw ApiError::message('You cannot restore yourself');
        }
        if ($member->atype === Membership::TYPE_OWNER && $headers->membership->atype !== Membership::TYPE_OWNER) {
            throw ApiError::message('Only owners can restore other owners');
        }

        $member->restore();
        // With the restored status.
        OrgPolicy::checkUserAllowed($member, 'restore');
        $member->save();
        self::logEvent(Event::ORGANIZATION_USER_RESTORED, $member->uuid, $orgId, $headers);
    }

    /**
     * FullCollectionData: name, group and member accesses, external id.
     *
     * @return array{string, list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>, list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>, ?string}
     *
     * @throws HttpStatus
     */
    private static function fullCollectionData(Fields $body): array
    {
        return [
            $body->string('name'),
            array_map(self::collectionAccessData(...), $body->objectList('groups')),
            array_map(self::collectionAccessData(...), $body->objectList('users')),
            $body->optionalString('externalId'),
        ];
    }

    /**
     * CollectionData, CollectionGroupData and CollectionMembershipData alike.
     *
     * @return array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}
     *
     * @throws HttpStatus
     */
    private static function collectionAccessData(Fields $access): array
    {
        return [
            'id' => $access->string('id'),
            'readOnly' => $access->bool('readOnly'),
            'hidePasswords' => $access->bool('hidePasswords'),
            'manage' => $access->bool('manage'),
        ];
    }

    /**
     * FullCollectionData::validate
     *
     * @param  list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>  $groups
     * @param  list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>  $users
     *
     * @throws ApiError
     */
    private static function validateCollectionAccess(string $orgId, array $groups, array $users): void
    {
        self::validateGroups($orgId, $groups);

        $members = Membership::findByOrg($orgId)->pluck('uuid')->all();
        foreach ($users as $user) {
            if (! in_array($user['id'], $members, true)) {
                throw ApiError::message('Invalid member', logMessage: 'Member '.EscapeDebug::of($user['id'])." does not belong to organization {$orgId}!");
            }
        }
    }

    /**
     * @param  list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>  $groups
     *
     * @throws ApiError
     */
    private static function validateGroups(string $orgId, array $groups): void
    {
        $orgGroups = self::groupIds($orgId);
        foreach ($groups as $group) {
            if (! in_array($group['id'], $orgGroups, true)) {
                throw ApiError::message('Invalid group', logMessage: 'Group '.EscapeDebug::of($group['id'])." does not belong to organization {$orgId}!");
            }
        }
    }

    /**
     * Replaces the group and member accesses of a collection.
     *
     * @param  list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>  $groups
     * @param  list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>  $users
     *
     * @throws ApiError
     */
    private static function replaceCollectionAccess(string $orgId, string $collectionId, array $groups, array $users): void
    {
        CollectionGroup::deleteAllByCollection($collectionId, $orgId);
        CollectionUser::deleteAllByCollection($collectionId);
        self::saveCollectionAccess($orgId, $collectionId, $groups, $users);
    }

    /**
     * Members with access to all need no entry.
     *
     * @param  list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>  $groups
     * @param  list<array{id: string, readOnly: bool, hidePasswords: bool, manage: bool}>  $users
     *
     * @throws ApiError
     */
    private static function saveCollectionAccess(string $orgId, string $collectionId, array $groups, array $users): void
    {
        foreach ($groups as $group) {
            (new CollectionGroup($collectionId, $group['id'], $group['readOnly'], $group['hidePasswords'], $group['manage']))->save($orgId);
        }

        foreach ($users as $user) {
            $member = Membership::findByUuidAndOrg($user['id'], $orgId) ?? throw ApiError::message('User is not part of organization');
            if (! $member->access_all) {
                CollectionUser::save($member->user_uuid, $collectionId, $user['readOnly'], $user['hidePasswords'], $user['manage']);
            }
        }
    }

    /**
     * @return array<string, int> Membership type by membership id
     */
    private static function membershipTypes(string $orgId): array
    {
        $types = [];
        foreach (Membership::findByOrg($orgId) as $member) {
            $types[$member->uuid] = $member->atype;
        }

        return $types;
    }

    /**
     * @return list<string>
     */
    private static function groupIds(string $orgId): array
    {
        return array_values(Group::findByOrganization($orgId)->map(static fn (Group $group): string => $group->uuid)->all());
    }

    /**
     * @throws ApiError
     */
    private static function addToGroup(string $orgId, string $groupId, string $memberId): void
    {
        Group::findByUuidAndOrg($groupId, $orgId) ?? throw ApiError::message('Group not found in Organization');
        (new GroupUser($groupId, $memberId))->save();
    }

    /**
     * The groups' accesses to a collection; none while groups are disabled,
     * as the clients ask regardless.
     *
     * @return list<array<string, mixed>>
     */
    private static function collectionGroups(string $collectionUuid): array
    {
        return Group::enabled()
            ? array_map(static fn (CollectionGroup $access): array => $access->toApiDetailsForGroup(), CollectionGroup::findByCollection($collectionUuid))
            : [];
    }

    /**
     * The `type` of InviteData and EditUserData, as NumberOrString::into_string.
     *
     * @throws HttpStatus
     */
    private static function rawType(Fields $body): string
    {
        $type = NumberOrString::optional($body, 'type') ?? throw new HttpStatus(422, 'Missing field `type`.');

        return (string) $type;
    }

    /**
     * The custom permissions, a map that defaults to empty.
     *
     * @return array<string, mixed>
     *
     * @throws HttpStatus
     */
    private static function permissions(Fields $body): array
    {
        $permissions = $body->value('permissions');
        if ($permissions === null) {
            return [];
        }
        if (! $permissions instanceof stdClass) {
            throw new HttpStatus(422, 'Field `permissions` must be a map.');
        }

        $map = [];
        foreach (get_object_vars($permissions) as $name => $value) {
            $map[(string) $name] = $value;
        }

        return $map;
    }

    /**
     * Admins and owners have access to all; so does a custom user whose three
     * collection permissions are all set.
     *
     * @param  array<string, mixed>  $permissions
     */
    private static function accessAll(int $type, string $rawType, array $permissions): bool
    {
        return Membership::typeAtLeast($type, Membership::TYPE_ADMIN)
            || ($rawType === '4'
                && ($permissions['editAnyCollection'] ?? null) === true
                && ($permissions['deleteAnyCollection'] ?? null) === true
                && ($permissions['createNewCollections'] ?? null) === true);
    }

    /**
     * An Option<bool> query field: none when missing, repeated or no bool.
     */
    private static function optionalQueryBool(Request $request, string $name): ?bool
    {
        $values = Query::values($request, $name);
        if (count($values) !== 1) {
            return null;
        }

        return match (strtolower($values[0])) {
            'off', 'false', 'no' => false,
            '', 'on', 'true', 'yes' => true,
            default => null,
        };
    }

    /**
     * A list of per-member results, each with the error it ran into.
     *
     * @param  list<string>  $ids
     * @param  callable(string): void  $action
     */
    private static function bulkResponse(array $ids, string $object, string $verb, callable $action): Response
    {
        $responses = array_map(static fn (string $id): array => self::bulkItem($id, $object, $verb, static fn () => $action($id)), $ids);

        return Json::response(Json::sorted(['data' => $responses, 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * @param  callable(): void  $action
     * @return array<string, string>
     */
    private static function bulkItem(string $id, string $object, string $verb, callable $action): array
    {
        try {
            $action();
            $error = '';
        } catch (ApiError $exception) {
            // The details only go to the log.
            logger()->warning("Unable to {$verb} member ".EscapeDebug::of($id).": {$exception->debugText()}");
            $error = $exception->userMessage();
        }

        return ['error' => $error, 'id' => $id, 'object' => $object];
    }
}
