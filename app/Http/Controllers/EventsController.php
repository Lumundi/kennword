<?php

namespace App\Http\Controllers;

use App\Auth\AdminHeaders;
use App\Auth\Headers;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Data\Body;
use App\Http\Data\Fields;
use App\Http\Data\Query;
use App\Http\EmptyResponse;
use App\Http\HttpStatus;
use App\Http\Json;
use App\Models\Cipher;
use App\Models\Event;
use App\Models\Membership;
use App\Support\Dates;
use App\Support\Uuid;
use DateTimeImmutable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * src/api/core/events.rs: the organization event log, and the events the
 * clients collect. Without ORG_EVENTS_ENABLED the lists are empty, as the
 * clients ask regardless.
 */
final readonly class EventsController
{
    public function __construct(
        private Config $config,
    ) {}

    /**
     * GET /api/organizations/{org_id}/events?start=&end=&continuationToken=
     */
    public function getOrgEvents(AdminHeaders $headers, Request $request, string $orgId): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $range = self::eventRange($request);
        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Organization not found', logMessage: "Organization id's do not match");
        }

        $events = new Collection;
        if ($this->config->bool('org_events_enabled')) {
            [$start, $end] = self::dateRange($range);
            $events = Event::findByOrganizationUuid($orgId, $start, $end);
        }

        return self::list($events);
    }

    /**
     * GET /api/ciphers/{cipher_id}/events: for owners and admins of the cipher's organization.
     */
    public function getCipherEvents(Headers $headers, Request $request, string $cipherId): Response
    {
        $cipherId = Uuid::parameter($request, $cipherId);
        $range = self::eventRange($request);

        $events = new Collection;
        if ($this->config->bool('org_events_enabled') && Membership::userHasGeAdminAccessToCipher($headers->user->uuid, $cipherId)) {
            [$start, $end] = self::dateRange($range);
            $events = Event::findByCipherUuid($cipherId, $start, $end);
        }

        return self::list($events);
    }

    /**
     * GET /api/organizations/{org_id}/users/{member_id}/events
     */
    public function getUserEvents(AdminHeaders $headers, Request $request, string $orgId, string $memberId): Response
    {
        $orgId = Uuid::parameter($request, $orgId);
        $memberId = Uuid::parameter($request, $memberId);
        $range = self::eventRange($request);
        if ($orgId !== $headers->membership->org_uuid) {
            throw ApiError::message('Organization not found', logMessage: "Organization id's do not match");
        }

        $events = new Collection;
        if ($this->config->bool('org_events_enabled')) {
            [$start, $end] = self::dateRange($range);
            $events = Event::findByOrgAndMember($orgId, $memberId, $start, $end);
        }

        return self::list($events);
    }

    /**
     * POST /events/collect: the few events clients may log, for what the
     * user can actually reach.
     */
    public function postEventsCollect(Headers $headers, Request $request): EmptyResponse
    {
        // format = "application/json": other bodies match no route.
        if (! str_starts_with(strtolower((string) $request->headers->get('Content-Type')), 'application/json')) {
            throw new HttpStatus(404, 'Not a JSON body.');
        }
        $events = Body::jsonList($request);
        $events = array_map(static fn (Fields $event): array => [
            'type' => $event->int('type'),
            'date' => $event->string('date'),
            'cipherId' => $event->optionalString('cipherId'),
            'organizationId' => $event->optionalString('organizationId'),
        ], $events);

        if (! $this->config->bool('org_events_enabled')) {
            return new EmptyResponse;
        }

        $user = $headers->user;
        foreach ($events as $event) {
            $date = Dates::parseUtc($event['date']) ?? throw ApiError::message('Invalid event date');
            $type = $event['type'];
            $orgId = $event['organizationId'];

            if ($type === Event::USER_CLIENT_EXPORTED_VAULT) {
                Event::logUserImpl($type, $user->uuid, $headers->device->atype, $date, $headers->ip);
            } elseif ($type === Event::ORGANIZATION_CLIENT_EXPORTED_VAULT) {
                // Only for an organization the user is a member of.
                if ($orgId !== null && Membership::findConfirmedByUserAndOrg($user->uuid, $orgId) !== null) {
                    Event::logImpl($type, $orgId, $orgId, $user->uuid, $headers->device->atype, $date, $headers->ip);
                }
            } elseif ($type === Event::ORGANIZATION_USER_NOTIFICATION_BANNER_ACTION_CLICKED) {
                // The only member event a client may log; the others come from the server.
                $membership = $orgId === null ? null : Membership::findConfirmedByUserAndOrg($user->uuid, $orgId);
                if ($orgId !== null && $membership !== null) {
                    Event::logImpl($type, $membership->uuid, $orgId, $user->uuid, $headers->device->atype, $date, $headers->ip);
                }
            } elseif (($type >= 1107 && $type <= 1114) || $type === 1117 || ($type >= 1119 && $type <= 1133)) {
                // Cipher events of the client (viewed, copied, toggled, autofilled, HTTP auth) go to the cipher's organization.
                $cipher = $event['cipherId'] === null ? null : Cipher::findByUuid($event['cipherId']);
                if ($event['cipherId'] !== null && $cipher !== null && $cipher->isAccessibleToUser($user->uuid) && $cipher->organization_uuid !== null) {
                    Event::logImpl($type, $event['cipherId'], $cipher->organization_uuid, $user->uuid, $headers->device->atype, $date, $headers->ip);
                }
            }
        }

        return new EmptyResponse;
    }

    /**
     * EventRange: start and end are required (the route does not match
     * without them), the continuation token optional.
     *
     * @return array{start: string, end: string, continuationToken: ?string}
     *
     * @throws HttpStatus
     */
    private static function eventRange(Request $request): array
    {
        $start = Query::first($request, 'start');
        $end = Query::first($request, 'end');
        if ($start === null || $end === null) {
            throw new HttpStatus(404, 'The event range is missing.');
        }
        $tokens = Query::values($request, 'continuationToken');

        return ['start' => $start, 'end' => $end, 'continuationToken' => count($tokens) === 1 ? $tokens[0] : null];
    }

    /**
     * EventRange::date_range: a continuation token replaces the end.
     *
     * @param  array{start: string, end: string, continuationToken: ?string}  $range
     * @return array{DateTimeImmutable, DateTimeImmutable}
     *
     * @throws ApiError
     */
    private static function dateRange(array $range): array
    {
        return [
            Dates::parseUtc($range['start']) ?? throw ApiError::message('Invalid start date'),
            Dates::parseUtc($range['continuationToken'] ?? $range['end']) ?? throw ApiError::message('Invalid end date'),
        ];
    }

    /**
     * With a full page, the date of its last event continues the list.
     *
     * @param  Collection<int, Event>  $events
     */
    private static function list(Collection $events): Response
    {
        $data = array_values($events->map(static fn (Event $event): array => $event->toApi())->all());
        $last = end($data);
        $token = count($data) === Event::PAGE_SIZE && $last !== false ? $last['date'] : null;

        return Json::response(Json::sorted(['data' => $data, 'object' => 'list', 'continuationToken' => $token]));
    }
}
