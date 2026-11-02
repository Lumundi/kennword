<?php

namespace App\Auth\Sso;

use App\Config\Config;
use App\Http\ApiError;
use App\Models\SsoAuth;
use App\Support\EscapeDebug;
use App\Support\FormUrlencoded;
use App\Support\HttpClient;
use App\Support\Random;
use Illuminate\Support\Facades\Cache;
use stdClass;
use Throwable;

/**
 * src/sso_client.rs with what it takes from the openidconnect and oauth2
 * crates: discovery of the provider (and its keys), the authorization URL,
 * the code and refresh token exchanges with their ID token checks, and the
 * user info. The discovered provider is cached for
 * SSO_CLIENT_CACHE_EXPIRATION seconds, refresh results for 30 seconds.
 */
final readonly class OidcClient
{
    private const string CACHE_KEY = 'sso-client';

    /**
     * @param  list<stdClass>  $keys  The provider's JWK set
     * @param  list<string>  $signingAlgorithms  id_token_signing_alg_values_supported
     */
    private function __construct(
        private Config $config,
        private string $issuer,
        private string $authorizationEndpoint,
        private string $tokenEndpoint,
        private string $userInfoEndpoint,
        private array $keys,
        private bool $basicAuth,
        private array $signingAlgorithms,
    ) {}

    /**
     * Client::cached: the discovered provider, from the cache while SSO_CLIENT_CACHE_EXPIRATION allows.
     *
     * @throws ApiError
     */
    public static function cached(Config $config): self
    {
        $expiration = $config->int('sso_client_cache_expiration');
        if ($expiration <= 0) {
            return self::discover($config);
        }

        $cached = Cache::get(self::CACHE_KEY);
        if (is_array($cached)) {
            $client = self::fromArray($config, $cached);
            if ($client !== null) {
                return $client;
            }
        }
        $client = self::discover($config);
        Cache::put(self::CACHE_KEY, $client->toArray(), $expiration);

        return $client;
    }

    public static function invalidate(Config $config): void
    {
        if ($config->int('sso_client_cache_expiration') > 0) {
            Cache::forget(self::CACHE_KEY);
        }
    }

    /**
     * Client::authorize_url: where the user logs in at the provider, and the
     * login in progress. The state is passed on base64 encoded.
     *
     * @return array{string, SsoAuth}
     *
     * @throws ApiError
     */
    public static function authorizeUrl(Config $config, string $state, string $clientChallenge, string $redirectUri, ?string $bindingHash): array
    {
        $client = self::cached($config);
        $nonce = rtrim(Random::base64Url(16), '=');
        $scopes = implode(' ', ['openid', ...preg_split('/\s+/', $config->string('sso_scopes'), flags: PREG_SPLIT_NO_EMPTY) ?: []]);

        $pairs = [
            ['response_type', 'code'],
            ['client_id', $config->string('sso_client_id')],
            ['state', base64_encode($state)],
            ['redirect_uri', $config->string('sso_callback_path')],
            ['scope', $scopes],
            ...FormUrlencoded::parse($config->string('sso_authorize_extra_params')),
        ];
        if ($config->bool('sso_pkce')) {
            $pairs[] = ['code_challenge', $clientChallenge];
            $pairs[] = ['code_challenge_method', 'S256'];
        }
        $pairs[] = ['nonce', $nonce];

        return [
            FormUrlencoded::appendPairs($client->authorizationEndpoint, $pairs),
            SsoAuth::new($state, $clientChallenge, $nonce, $redirectUri, $bindingHash),
        ];
    }

    /**
     * Client::check_client_verifier: the verifier must hash to the challenge the client started with.
     *
     * @throws ApiError
     */
    public static function checkClientVerifier(string $clientVerifier, SsoAuth $auth): void
    {
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $clientVerifier, true)), '+/', '-_'), '=');
        if ($challenge !== $auth->client_challenge) {
            throw ApiError::message('PKCE client challenge failed');
        }
    }

    /**
     * Client::exchange_code: the tokens for the code, with the verified claims of the ID token.
     *
     * @return array{stdClass, stdClass} The token response and the ID token claims
     *
     * @throws ApiError
     */
    public function exchangeCode(string $code, string $clientVerifier, SsoAuth $auth): array
    {
        $params = [['grant_type', 'authorization_code'], ['code', $code]];
        if ($this->config->bool('sso_pkce')) {
            $params[] = ['code_verifier', $clientVerifier];
        } else {
            self::checkClientVerifier($clientVerifier, $auth);
        }
        $params[] = ['redirect_uri', $this->config->string('sso_callback_path')];

        try {
            $tokens = $this->tokenRequest($params);
        } catch (TokenRequestError $error) {
            throw ApiError::message("Failed to contact token endpoint: {$error->getMessage()}");
        }

        $idToken = $tokens->id_token ?? null;
        if (! is_string($idToken)) {
            throw ApiError::message('Token response did not contain an id_token');
        }

        try {
            $claims = $this->verifiedIdTokenClaims($idToken, $auth->nonce);
        } catch (ClaimsVerificationError $error) {
            self::invalidate($this->config);

            throw ApiError::message("Could not read id_token claims, {$error->getMessage()}");
        }

        return [$tokens, $claims];
    }

    /**
     * Client::user_info
     *
     * @throws ApiError
     */
    public function userInfo(string $accessToken): stdClass
    {
        try {
            [$status, $body, $headers] = HttpClient::send('GET', $this->userInfoEndpoint, [
                'Accept' => 'application/json',
                'Authorization' => "Bearer {$accessToken}",
            ], enforceBlock: false, redirects: false);
        } catch (ApiError) {
            throw ApiError::message('Request to user_info endpoint failed: Request failed');
        }

        if ($status !== 200) {
            throw ApiError::message('Request to user_info endpoint failed: Server returned invalid response: unexpected HTTP status code');
        }
        $contentType = $headers['content-type'] ?? 'application/json';
        if (! self::hasEssence($contentType, 'application/json')) {
            throw ApiError::message('Request to user_info endpoint failed: Other error: unexpected response Content-Type: '.EscapeDebug::debug($contentType));
        }
        $claims = json_decode($body);
        if (! $claims instanceof stdClass || ! is_string($claims->sub ?? null) || ! self::hasBooleanClaims($claims)) {
            throw ApiError::message('Request to user_info endpoint failed: Failed to parse server response');
        }

        return $claims;
    }

    /**
     * Client::check_validity: an access token without refresh token stays valid while the provider still answers to it.
     *
     * @throws ApiError
     */
    public static function checkValidity(Config $config, string $accessToken): void
    {
        $client = self::cached($config);
        try {
            $client->userInfo($accessToken);
        } catch (ApiError $error) {
            throw ApiError::silent("Failed to retrieve user info, token has probably been invalidated: {$error->getMessage()}");
        }
    }

    /**
     * Client::exchange_refresh_token: the new refresh token (if any), the
     * access token and its lifetime. A result, error or not, is reused for 30
     * seconds, so that clients refreshing at once do not use the token twice.
     *
     * @return array{?string, string, ?int}
     *
     * @throws ApiError
     */
    public static function exchangeRefreshToken(Config $config, string $refreshToken): array
    {
        $client = self::cached($config);
        $key = 'sso-refresh-'.hash('sha256', $refreshToken);

        $result = Cache::get($key);
        if (! is_array($result)) {
            try {
                $tokens = $client->tokenRequest([['grant_type', 'refresh_token'], ['refresh_token', $refreshToken]]);
                $result = ['refresh_token' => self::stringField($tokens, 'refresh_token'), 'access_token' => self::stringField($tokens, 'access_token'),
                    'expires_in' => self::expiresIn($tokens)];
            } catch (TokenRequestError $error) {
                logger()->error("Request to exchange_refresh_token endpoint failed: {$error->display}");
                $result = ['error' => "Request to exchange_refresh_token endpoint failed: {$error->display}"];
            }
            Cache::put($key, $result, 30);
        }

        $error = $result['error'] ?? null;
        if (is_string($error)) {
            throw ApiError::message($error);
        }
        $newRefreshToken = $result['refresh_token'] ?? null;
        $accessToken = $result['access_token'] ?? null;
        $expiresIn = $result['expires_in'] ?? null;

        return [is_string($newRefreshToken) ? $newRefreshToken : null, is_string($accessToken) ? $accessToken : '', is_int($expiresIn) ? $expiresIn : null];
    }

    /**
     * A string field of a token response or claims, or null.
     */
    public static function stringField(stdClass $object, string $name): ?string
    {
        $value = $object->{$name} ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * expires_in of a token response, in seconds.
     */
    public static function expiresIn(stdClass $tokens): ?int
    {
        $expiresIn = $tokens->expires_in ?? null;

        return is_int($expiresIn) && $expiresIn >= 0 ? $expiresIn : null;
    }

    /**
     * Client::get_client: CoreProviderMetadata::discover_async and the client made from it.
     *
     * @throws ApiError
     */
    private static function discover(Config $config): self
    {
        $issuer = $config->string('sso_authority');
        $discoveryUrl = (str_ends_with($issuer, '/') ? $issuer : "{$issuer}/").'.well-known/openid-configuration';

        try {
            $metadata = self::fetchJson($discoveryUrl, ['application/json']);
            $metadataIssuer = self::stringField($metadata, 'issuer');
            $authorizationEndpoint = self::stringField($metadata, 'authorization_endpoint');
            $jwksUri = self::stringField($metadata, 'jwks_uri');
            $signingAlgorithms = $metadata->id_token_signing_alg_values_supported ?? null;
            if ($metadataIssuer === null || $authorizationEndpoint === null || $jwksUri === null || ! is_array($signingAlgorithms)
                || ! is_array($metadata->response_types_supported ?? null) || ! is_array($metadata->subject_types_supported ?? null)) {
                throw new DiscoveryError('Failed to parse server response');
            }
            if ($metadataIssuer !== $issuer) {
                throw new DiscoveryError("Validation error: unexpected issuer URI `{$metadataIssuer}` (expected `{$issuer}`)");
            }
            $jwks = self::fetchJson($jwksUri, ['application/json', 'application/jwk-set+json']);
        } catch (DiscoveryError $error) {
            throw ApiError::message("Failed to discover OpenID provider: {$error->getMessage()}");
        }

        $methods = $metadata->token_endpoint_auth_methods_supported ?? null;
        $basicAuth = true;
        if (is_array($methods)) {
            if (in_array('client_secret_basic', $methods, true)) {
                $basicAuth = true;
            } elseif (in_array('client_secret_post', $methods, true)) {
                $basicAuth = false;
            } else {
                $advertised = implode(', ', array_map(static fn (mixed $method): string => is_string($method) ? self::authMethodDebug($method) : '?', $methods));
                throw ApiError::message("No supported auth_methods (only basic or request body), advertised: {{$advertised}}");
            }
        }

        $tokenEndpoint = $metadata->token_endpoint ?? null;
        if (! is_string($tokenEndpoint)) {
            throw ApiError::message('Failed to discover token_url, cannot proceed');
        }
        $userInfoEndpoint = $metadata->userinfo_endpoint ?? null;
        if (! is_string($userInfoEndpoint)) {
            throw ApiError::message('Failed to discover user_info url, cannot proceed');
        }

        $keys = is_array($jwks->keys ?? null) ? array_values(array_filter($jwks->keys, static fn (mixed $key): bool => $key instanceof stdClass)) : [];
        $algorithms = array_values(array_filter($signingAlgorithms, is_string(...)));

        return new self($config, $metadataIssuer, $authorizationEndpoint, $tokenEndpoint, $userInfoEndpoint, $keys, $basicAuth, $algorithms);
    }

    /**
     * GET with Accept: application/json; the answer must be 200 with one of the content types, or none.
     *
     * @param  list<string>  $contentTypes
     *
     * @throws DiscoveryError
     */
    private static function fetchJson(string $url, array $contentTypes): stdClass
    {
        try {
            [$status, $body, $headers] = HttpClient::send('GET', $url, ['Accept' => 'application/json'], enforceBlock: false, redirects: false);
        } catch (ApiError) {
            throw new DiscoveryError('Request failed');
        }
        if ($status !== 200) {
            throw new DiscoveryError("Server returned invalid response: HTTP status code {$status} ".self::reason($status)." at {$url}");
        }
        $contentType = $headers['content-type'] ?? null;
        if ($contentType !== null && ! array_filter($contentTypes, static fn (string $type): bool => self::hasEssence($contentType, $type))) {
            throw new DiscoveryError('Server returned invalid response: Unexpected response Content-Type: '.EscapeDebug::debug($contentType).", should be `{$contentTypes[0]}`");
        }
        $json = json_decode($body);
        if (! $json instanceof stdClass) {
            throw new DiscoveryError('Failed to parse server response');
        }

        return $json;
    }

    /**
     * oauth2's token request: the form with the client's credentials, as
     * Basic authentication or in the body, and the JSON answer.
     *
     * @param  list<array{string, string}>  $params
     *
     * @throws TokenRequestError
     */
    private function tokenRequest(array $params): stdClass
    {
        $clientId = $this->config->string('sso_client_id');
        $secret = $this->config->string('sso_client_secret');
        $headers = ['Accept' => 'application/json', 'Content-Type' => 'application/x-www-form-urlencoded'];
        if ($this->basicAuth) {
            $headers['Authorization'] = 'Basic '.base64_encode(FormUrlencoded::component($clientId).':'.FormUrlencoded::component($secret));
        } else {
            $params[] = ['client_id', $clientId];
            $params[] = ['client_secret', $secret];
        }

        try {
            [$status, $body, $responseHeaders] = HttpClient::send('POST', $this->tokenEndpoint, $headers, FormUrlencoded::encodePairs($params), enforceBlock: false, redirects: false);
        } catch (ApiError $error) {
            throw new TokenRequestError('Request('.EscapeDebug::debug($error->getMessage()).')', 'Request failed');
        }

        if ($status !== 200) {
            if ($body === '') {
                throw new TokenRequestError('Other("server returned empty error response")', 'Other error: server returned empty error response');
            }
            $error = json_decode($body);
            if (! $error instanceof stdClass || ! is_string($error->error ?? null)) {
                throw new TokenRequestError('Parse(..)', 'Failed to parse server response');
            }

            throw new TokenRequestError(self::serverResponseDebug($error), 'Server returned error response: '.self::serverResponseDisplay($error));
        }
        $contentType = $responseHeaders['content-type'] ?? null;
        if ($contentType !== null && ! self::hasEssence($contentType, 'application/json')) {
            $other = 'Unexpected response Content-Type: '.EscapeDebug::debug($contentType).', should be `application/json`';

            throw new TokenRequestError('Other('.EscapeDebug::debug($other).')', "Other error: {$other}");
        }

        $tokens = json_decode($body);
        if (! $tokens instanceof stdClass || ! is_string($tokens->access_token ?? null) || ! is_string($tokens->token_type ?? null)
            || strtolower($tokens->token_type) !== 'bearer') {
            throw new TokenRequestError('Parse(..)', 'Failed to parse server response');
        }
        // The ID token's claims are parsed with the response.
        $idToken = is_string($tokens->id_token ?? null) ? Jws::parse($tokens->id_token) : null;
        if ($idToken !== null && ! self::hasBooleanClaims($idToken->payload)) {
            throw new TokenRequestError('Parse(..)', 'Failed to parse server response');
        }

        return $tokens;
    }

    /**
     * The boolean claims of StandardClaims are booleans or null: Vaultwarden
     * builds openidconnect without accept-string-booleans, so "false" fails
     * to parse rather than leaving the email's verification unknown.
     */
    private static function hasBooleanClaims(stdClass $claims): bool
    {
        foreach (['email_verified', 'phone_number_verified'] as $name) {
            $value = $claims->{$name} ?? null;
            if ($value !== null && ! is_bool($value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * CoreIdTokenVerifier with SSO_AUDIENCE_TRUSTED (vw_id_token_verifier) and the nonce check.
     *
     * @throws ClaimsVerificationError
     */
    private function verifiedIdTokenClaims(string $idToken, string $nonce): stdClass
    {
        $jws = Jws::parse($idToken) ?? throw new ClaimsVerificationError('Signature verification failed');
        $claims = $jws->payload;
        $clientId = $this->config->string('sso_client_id');

        $type = $jws->header->typ ?? null;
        if (is_string($type) && ! in_array(strtolower($type), ['jwt', 'application/jwt', 'application/jose', 'jose'], true)) {
            throw new ClaimsVerificationError("Unsupported: unexpected or unsupported JWT type `{$type}`");
        }
        if (isset($jws->header->cty)) {
            throw new ClaimsVerificationError(is_string($jws->header->cty) && strtoupper($jws->header->cty) === 'JWT'
                ? 'Unsupported: nested JWT\'s are not currently supported'
                : 'Unsupported: unexpected or unsupported JWT content type `'.(is_string($jws->header->cty) ? $jws->header->cty : '').'`');
        }
        if (isset($jws->header->crit)) {
            throw new ClaimsVerificationError('Unsupported: critical JWT header fields are unsupported');
        }

        $issuer = $claims->iss ?? null;
        if (! is_string($issuer)) {
            throw new ClaimsVerificationError('Invalid issuer: missing issuer claim');
        }
        if ($issuer !== $this->issuer) {
            throw new ClaimsVerificationError("Invalid issuer: expected `{$this->issuer}` (found `{$issuer}`)");
        }

        $audiences = $claims->aud ?? null;
        $audiences = is_string($audiences) ? [$audiences] : (is_array($audiences) ? array_values(array_filter($audiences, is_string(...))) : null);
        if ($audiences === null) {
            throw new ClaimsVerificationError('Invalid audiences: missing audiences claim');
        }
        if (! in_array($clientId, $audiences, true)) {
            $found = implode(', ', array_map(static fn (string $aud): string => "`{$aud}`", $audiences));
            throw new ClaimsVerificationError("Invalid audiences: must contain `{$clientId}` (found audiences: {$found})");
        }
        if (count($audiences) > 1) {
            $trusted = $this->config->optionalString('sso_audience_trusted');
            foreach ($audiences as $audience) {
                if ($audience !== $clientId && ! ($trusted !== null && @preg_match('/'.str_replace('/', '\/', $trusted).'/u', $audience) === 1)) {
                    throw new ClaimsVerificationError("Invalid audiences: `{$audience}` is not a trusted audience");
                }
            }
        }

        $algorithm = $jws->algorithm();
        if ($algorithm === null || ! Jws::isKnown($algorithm)) {
            throw new ClaimsVerificationError('Signature verification failed');
        }
        // SignatureVerification(DisallowedAlg(..)) shows only its own text.
        if (! in_array($algorithm, $this->signingAlgorithms, true)) {
            throw new ClaimsVerificationError('Signature verification failed');
        }
        if (Jws::usesSharedSecret($algorithm)) {
            $key = $this->config->string('sso_client_secret');
        } else {
            $keyId = $jws->header->kid ?? null;
            $keys = Jws::filterKeys($this->keys, is_string($keyId) ? $keyId : null, $algorithm);
            if (count($keys) !== 1) {
                throw new ClaimsVerificationError('Signature verification failed');
            }
            $key = $keys[0];
        }
        if (! $jws->verify($algorithm, $key)) {
            throw new ClaimsVerificationError('Signature verification failed');
        }

        $expiration = $claims->exp ?? null;
        if (! is_int($expiration) && ! is_float($expiration)) {
            throw new ClaimsVerificationError('Signature verification failed');
        }
        if (time() >= $expiration) {
            throw new ClaimsVerificationError('Expired: ID token expired at '.gmdate('Y-m-d H:i:s', (int) $expiration).' UTC');
        }
        if (! is_string($claims->sub ?? null) || (! is_int($claims->iat ?? null) && ! is_float($claims->iat ?? null))) {
            throw new ClaimsVerificationError('Signature verification failed');
        }

        $claimedNonce = $claims->nonce ?? null;
        if (! is_string($claimedNonce)) {
            throw new ClaimsVerificationError('Invalid nonce: missing nonce claim');
        }
        if (! hash_equals(hash('sha256', $nonce), hash('sha256', $claimedNonce))) {
            throw new ClaimsVerificationError('Invalid nonce: nonce mismatch');
        }

        return $claims;
    }

    /**
     * The Debug form of RequestTokenError::ServerResponse(StandardErrorResponse { .. }).
     * BasicErrorResponseType prints its code as it came, without quotes.
     */
    private static function serverResponseDebug(stdClass $error): string
    {
        $type = self::stringField($error, 'error') ?? '';
        $description = self::stringField($error, 'error_description');
        $uri = self::stringField($error, 'error_uri');
        $description = $description === null ? 'None' : 'Some('.EscapeDebug::debug($description).')';
        $uri = $uri === null ? 'None' : 'Some('.EscapeDebug::debug($uri).')';

        return "ServerResponse(StandardErrorResponse { error: {$type}, error_description: {$description}, error_uri: {$uri} })";
    }

    /**
     * The Display form of StandardErrorResponse: the code, then ": description" and " (see uri)".
     */
    private static function serverResponseDisplay(stdClass $error): string
    {
        $description = self::stringField($error, 'error_description');
        $uri = self::stringField($error, 'error_uri');

        return (self::stringField($error, 'error') ?? '').($description === null ? '' : ": {$description}").($uri === null ? '' : " (see {$uri})");
    }

    private static function authMethodDebug(string $method): string
    {
        return [
            'client_secret_basic' => 'ClientSecretBasic', 'client_secret_jwt' => 'ClientSecretJwt', 'client_secret_post' => 'ClientSecretPost',
            'none' => 'None', 'private_key_jwt' => 'PrivateKeyJwt', 'tls_client_auth' => 'TlsClientAuth', 'self_signed_tls_client_auth' => 'SelfSignedTlsClientAuth',
        ][$method] ?? 'Extension('.EscapeDebug::debug($method).')';
    }

    /**
     * content_type_has_essence: the media type without parameters, any case.
     */
    private static function hasEssence(string $contentType, string $expected): bool
    {
        return strtolower(trim(explode(';', $contentType)[0])) === $expected;
    }

    private static function reason(int $status): string
    {
        return [400 => 'Bad Request', 401 => 'Unauthorized', 403 => 'Forbidden', 404 => 'Not Found', 500 => 'Internal Server Error',
            502 => 'Bad Gateway', 503 => 'Service Unavailable'][$status] ?? '';
    }

    /**
     * @return array<string, mixed>
     */
    private function toArray(): array
    {
        return [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->authorizationEndpoint,
            'token_endpoint' => $this->tokenEndpoint,
            'userinfo_endpoint' => $this->userInfoEndpoint,
            'keys' => json_encode($this->keys),
            'basic_auth' => $this->basicAuth,
            'algorithms' => $this->signingAlgorithms,
        ];
    }

    /**
     * @param  array<mixed>  $data
     */
    private static function fromArray(Config $config, array $data): ?self
    {
        try {
            $keys = json_decode(is_string($data['keys'] ?? null) ? $data['keys'] : '', flags: JSON_THROW_ON_ERROR);
            $algorithms = $data['algorithms'] ?? null;
            if (! is_array($keys) || ! is_array($algorithms) || ! is_string($data['issuer'] ?? null) || ! is_string($data['authorization_endpoint'] ?? null)
                || ! is_string($data['token_endpoint'] ?? null) || ! is_string($data['userinfo_endpoint'] ?? null) || ! is_bool($data['basic_auth'] ?? null)) {
                return null;
            }

            return new self($config, $data['issuer'], $data['authorization_endpoint'], $data['token_endpoint'], $data['userinfo_endpoint'],
                array_values(array_filter($keys, static fn (mixed $key): bool => $key instanceof stdClass)), $data['basic_auth'],
                array_values(array_filter($algorithms, is_string(...))));
        } catch (Throwable) {
            return null;
        }
    }
}
