<?php

namespace App\Http\Controllers;

use App\Auth\Headers;
use App\Config\Config;
use App\Config\FeatureFlags;
use App\Http\ApiError;
use App\Http\Data\Body;
use App\Http\Data\Query;
use App\Http\HttpStatus;
use App\Http\Json;
use App\Models\User;
use App\Notifications\Notify;
use App\Support\Dates;
use App\Support\FormUrlencoded;
use App\Support\HttpClient;
use App\Support\JsonValue;
use App\Support\UpdateType;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use LogicException;
use stdClass;

/**
 * src/api/core/mod.rs
 */
final readonly class CoreController
{
    public function __construct(
        private WebController $web,
        private Notify $nt,
    ) {}

    /**
     * GET /api/alive
     */
    public function alive(): Response
    {
        return $this->web->alive();
    }

    /**
     * GET /api/now
     */
    public function now(): Response
    {
        return Json::response(Dates::format(Dates::now()));
    }

    /**
     * GET /api/version
     */
    public function version(): Response
    {
        return Json::response(config()->string('vaultwarden.version'));
    }

    /**
     * GET /api/config: what the clients learn of the server. The server is
     * named Kennword, so that users find the source and report bugs
     * here (AGPL section 13); the rest is as Vaultwarden says it.
     */
    public function config(Config $config): Response
    {
        $domain = $config->string('domain');
        $featureStates = FeatureFlags::parse($config->string('experimental_client_feature_flags'), 'valid');
        $featureStates['pm-19148-innovation-archive'] = true;

        return Json::response(Json::sorted([
            // The clients compare it with Bitwarden server versions.
            'version' => '2026.6.0',
            'gitHash' => null,
            'server' => ['name' => 'Kennword', 'url' => 'https://github.com/Lumundi/kennword'],
            'settings' => [
                'disableUserRegistration' => $config->isSignupDisabled(),
                'suppressOnboardingInterstitials' => $config->bool('client_suppress_onboarding'),
            ],
            'environment' => [
                'vault' => $domain,
                'api' => "{$domain}/api",
                'identity' => "{$domain}/identity",
                'notifications' => "{$domain}/notifications",
                'sso' => '',
                'cloudRegion' => null,
                'fillAssistRules' => $config->string('fill_assist_rules_url'),
            ],
            'push' => ['pushTechnology' => 0, 'vapidPublicKey' => null],
            'featureStates' => $featureStates,
            'communication' => null,
            'object' => 'config',
        ]));
    }

    /**
     * GET /api/hibp/breach?username=: the breaches HaveIBeenPwned knows, with
     * HIBP_API_KEY; without it, a pointer to the manual check.
     */
    public function hibpBreach(Request $request, Config $config): Response
    {
        // Without the parameter the route does not match.
        $username = FormUrlencoded::component(Query::first($request, 'username') ?? throw new HttpStatus(404, 'No username.'));
        app(Headers::class);

        $apiKey = $config->optionalString('hibp_api_key');
        if ($apiKey === null) {
            return Json::response([Json::sorted([
                'name' => 'HaveIBeenPwned',
                'title' => 'Manual HIBP Check',
                'domain' => 'haveibeenpwned.com',
                'breachDate' => '2019-08-18T00:00:00Z',
                'addedDate' => '2019-08-18T00:00:00Z',
                'description' => "Go to: <a href=\"https://haveibeenpwned.com/account/{$username}\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/account/{$username}</a> for a manual check.<br/><br/>HaveIBeenPwned API key not set!<br/>Go to <a href=\"https://haveibeenpwned.com/API/Key\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/API/Key</a> to purchase an API key from HaveIBeenPwned.<br/><br/>",
                'logoPath' => 'vw_static/hibp.png',
                'pwnCount' => 0,
                'dataClasses' => ['Error - No API key set!'],
            ])]);
        }

        try {
            [$status, $body] = HttpClient::send('GET', "https://haveibeenpwned.com/api/v3/breachedaccount/{$username}?truncateResponse=false&includeUnverified=false",
                ['hibp-api-key' => $apiKey]);
        } catch (ApiError) {
            throw ApiError::message('Req');
        }
        // No breaches.
        if ($status === 404) {
            throw ApiError::empty(404);
        }
        [$ok, $value] = JsonValue::decode($body);
        if ($status >= 400 || ! $ok) {
            throw ApiError::message('Req');
        }

        return Json::response($value);
    }

    /**
     * GET /api/webauthn: the passkeys for logging in, which Vaultwarden does
     * not support; an empty list keeps key rotation working.
     */
    public function getApiWebauthn(Headers $headers): Response
    {
        return Json::response(Json::sorted(['object' => 'list', 'data' => [], 'continuationToken' => null]));
    }

    /**
     * GET /api/settings/domains
     */
    public function getSettingsDomains(Headers $headers): Response
    {
        return Json::response(self::eqDomains($headers->user, noExcluded: false));
    }

    /**
     * POST /api/settings/domains, also PUT
     */
    public function postSettingsDomains(Headers $headers, Request $request): Response
    {
        $body = Body::json($request);
        $excluded = $body->value('excludedGlobalEquivalentDomains') ?? [];
        $equivalent = $body->value('equivalentDomains') ?? [];

        // Option<Vec<i32>> and Option<Vec<Vec<String>>>
        if (! is_array($excluded) || ! array_is_list($excluded)) {
            throw new HttpStatus(422, 'Field `excludedGlobalEquivalentDomains` must be a sequence.');
        }
        foreach ($excluded as $type) {
            if (! is_int($type) || $type < -2147483648 || $type > 2147483647) {
                throw new HttpStatus(422, 'Field `excludedGlobalEquivalentDomains` must hold i32s.');
            }
        }
        if (! is_array($equivalent) || ! array_is_list($equivalent)) {
            throw new HttpStatus(422, 'Field `equivalentDomains` must be a sequence.');
        }
        foreach ($equivalent as $group) {
            if (! is_array($group) || ! array_is_list($group) || array_filter($group, is_string(...)) !== $group) {
                throw new HttpStatus(422, 'Field `equivalentDomains` must hold sequences of strings.');
            }
        }

        $user = $headers->user;
        $user->excluded_globals = Json::encode($excluded);
        $user->equivalent_domains = Json::encode($equivalent);
        $user->save();

        $this->nt->sendUserUpdate(UpdateType::SyncSettings, $user, $headers->device->push_uuid);

        return Json::response(new stdClass);
    }

    /**
     * core::get_eq_domains: the user's own groups of equivalent domains and the
     * global ones, marked as excluded by the user or left out.
     *
     * @return array<string, mixed>
     */
    public static function eqDomains(User $user, bool $noExcluded): array
    {
        // Upstream unwraps these; values it did not write itself make it panic.
        [$ok, $equivalent] = JsonValue::decode($user->equivalent_domains);
        if (! $ok || ! is_array($equivalent) || ! array_is_list($equivalent)) {
            throw new LogicException('Invalid equivalent_domains of user '.$user->uuid);
        }
        [$ok, $excluded] = JsonValue::decode($user->excluded_globals);
        if (! $ok || ! is_array($excluded) || ! array_is_list($excluded)) {
            throw new LogicException('Invalid excluded_globals of user '.$user->uuid);
        }

        $globals = [];
        foreach (self::globalDomains() as $global) {
            $global['excluded'] = in_array($global['type'], $excluded, true);
            if (! $noExcluded || ! $global['excluded']) {
                $globals[] = $global;
            }
        }

        return Json::sorted([
            'equivalentDomains' => $equivalent,
            'globalEquivalentDomains' => $globals,
            'object' => 'domains',
        ]);
    }

    /**
     * src/static/global_domains.json
     *
     * @return list<array{type: int, domains: list<string>, excluded: bool}>
     */
    private static function globalDomains(): array
    {
        /** @var list<array{type: int, domains: list<string>, excluded: bool}> */
        return json_decode((string) file_get_contents(resource_path('vaultwarden/static/global_domains.json')), true, 512, JSON_THROW_ON_ERROR);
    }
}
