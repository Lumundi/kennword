<?php

namespace App\Auth;

use App\Config\Config;
use App\Http\Unauthorized;
use App\Models\OrganizationApiKey;
use Illuminate\Http\Request;
use LogicException;
use Throwable;

/**
 * api::core::public::PublicToken: the access token an organization API key
 * gets from /identity/connect/token, for the public API.
 */
final readonly class PublicToken
{
    public function __construct(
        public string $orgId,
    ) {}

    /**
     * @throws Unauthorized
     */
    public static function fromRequest(Request $request, Config $config, Jwt $jwt): self
    {
        $authorization = $request->headers->get('Authorization') ?? throw new Unauthorized('No access token provided');
        // Everything after the last "Bearer ", or the whole header without one.
        $position = strrpos($authorization, 'Bearer ');
        $token = $position === false ? $authorization : substr($authorization, $position + strlen('Bearer '));

        try {
            $claims = $jwt->decode($token, JwtIssuer::OrgApiKey);
        } catch (Throwable) {
            throw new Unauthorized('Invalid claim');
        }
        // OrgApiKeyLoginJwtClaims
        [$nbf, $exp, $iss, $sub, $clientId, $clientSub, $scope] = [$claims['nbf'] ?? null, $claims['exp'] ?? null, $claims['iss'] ?? null,
            $claims['sub'] ?? null, $claims['client_id'] ?? null, $claims['client_sub'] ?? null, $claims['scope'] ?? null];
        if (! is_int($nbf) || ! is_int($exp) || ! is_string($iss) || ! is_string($sub) || ! is_string($clientId) || ! is_string($clientSub)
            || ! is_array($scope) || ! array_is_list($scope) || array_filter($scope, is_string(...)) !== $scope) {
            throw new Unauthorized('Invalid claim');
        }

        $now = time();
        if ($now < $nbf) {
            throw new Unauthorized('Token issued in the future');
        }
        if ($now > $exp) {
            throw new Unauthorized('Token expired');
        }
        // Upstream indexes the scope without a check, which panics on an empty one.
        $firstScope = $scope[0] ?? throw new LogicException('The token has no scope');
        if ($iss !== $config->string('domain_origin').'|'.$firstScope) {
            throw new Unauthorized('Token not issued by this server');
        }

        $orgId = str_starts_with($clientId, 'organization.') ? substr($clientId, strlen('organization.')) : throw new Unauthorized('Malformed client_id');
        $apiKey = OrganizationApiKey::findByOrgUuid($orgId) ?? throw new Unauthorized('Invalid client_id');
        if ($apiKey->org_uuid !== $clientSub) {
            throw new Unauthorized('Token not issued for this org');
        }
        if ($apiKey->uuid !== $sub) {
            throw new Unauthorized('Token not issued for this client');
        }
        // Kennword: rotating the key ends the tokens it gave out. Rotation keeps the key's id and
        // sets its revision date; the token knows its issue time to the second only, so one issued
        // in the second of the rotation, before it, still passes.
        if ($nbf < $apiKey->revision_date->getTimestamp()) {
            throw new Unauthorized('Token issued before the API key was rotated');
        }

        return new self($clientSub);
    }
}
