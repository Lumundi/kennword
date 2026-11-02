<?php

namespace App\Support;

use App\Config\Config;
use App\Http\ApiError;
use App\Http\Json;
use App\Models\Cipher;
use App\Models\Device;
use App\Models\Folder;
use App\Models\Send;
use App\Models\User;
use Illuminate\Contracts\Cache\Repository;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/**
 * src/api/push.rs: mobile push notifications through Bitwarden's relay
 * (PUSH_ENABLED). Notifications Vaultwarden sends from a spawned task go
 * out once the response is sent.
 */
final class Push
{
    private const string TOKEN_CACHE_KEY = 'vaultwarden:push_token';

    /**
     * get_auth_api_token: kept for half of its lifetime.
     *
     * @throws ApiError
     */
    private static function authApiToken(): string
    {
        $cache = app(Repository::class);
        $token = $cache->get(self::TOKEN_CACHE_KEY);
        if (is_string($token) && $token !== '') {
            logger()->debug('Auth Push token still valid, no need for a new one');

            return $token;
        }

        $config = app(Config::class);
        $body = FormUrlencoded::encode([
            'grant_type' => 'client_credentials',
            'scope' => 'api.push',
            'client_id' => 'installation.'.$config->string('push_installation_id'),
            'client_secret' => $config->string('push_installation_key'),
        ]);
        try {
            [, $response] = self::request('POST', $config->string('push_identity_uri').'/connect/token',
                ['Content-Type' => 'application/x-www-form-urlencoded'], $body);
        } catch (RuntimeException $error) {
            throw ApiError::message("Error getting push token from bitwarden server: {$error->getMessage()}");
        }

        $json = json_decode($response, true);
        $token = is_array($json) ? ($json['access_token'] ?? null) : null;
        $expiresIn = is_array($json) ? ($json['expires_in'] ?? null) : null;
        if (! is_string($token) || ! is_int($expiresIn) || $expiresIn < -2147483648 || $expiresIn > 2147483647) {
            throw ApiError::message('Unexpected push token received from bitwarden server: error decoding response body');
        }

        // Token valid for half the specified time
        $valid = max(0, intdiv($expiresIn, 2));
        if ($valid > 0) {
            $cache->put(self::TOKEN_CACHE_KEY, $token, $valid);
        }
        logger()->debug("Token still valid for {$valid}");

        return $token;
    }

    /**
     * register_push_device: only mobile devices with a push token.
     *
     * @throws ApiError
     */
    public static function registerDevice(Device $device): void
    {
        $config = app(Config::class);
        if (! $config->bool('push_enabled') || ! $device->isPushDevice()) {
            return;
        }

        if ($device->push_token === null) {
            logger()->warning("Skipping the registration of the device \"{$device->uuid}\" because the push_token field is empty.");
            logger()->warning('To get rid of this message you need to logout, clear the app data and login again on the device.');

            return;
        }

        logger()->debug("Registering Device {$device->push_uuid}");

        // Generate a random push_uuid so if it doesn't already have one
        $device->push_uuid ??= Random::uuid();

        $data = Json::sorted([
            'deviceId' => $device->push_uuid,
            'pushToken' => $device->push_token,
            'userId' => $device->user_uuid,
            'type' => $device->atype,
            'identifier' => $device->uuid,
            'installationId' => $config->string('push_installation_id'),
        ]);

        $token = self::authApiToken();
        $url = $config->string('push_relay_uri').'/push/register';
        try {
            [$status] = self::request('POST', $url, [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'Authorization' => "Bearer {$token}",
            ], Json::encode($data));
        } catch (RuntimeException $error) {
            throw ApiError::message('Req', logMessage: $error->getMessage());
        }
        if ($status >= 400) {
            throw ApiError::message('An error occurred while proceeding registration of a device: '.self::statusError($status, $url));
        }

        try {
            $device->save();
        } catch (ApiError $error) {
            throw ApiError::message("An error occurred while trying to save the (registered) device push uuid: {$error->displayText()}");
        }
    }

    /**
     * unregister_push_device
     *
     * @throws ApiError
     */
    public static function unregisterDevice(?string $pushUuid): void
    {
        $config = app(Config::class);
        if (! $config->bool('push_enabled') || $pushUuid === null) {
            return;
        }
        $data = ['id' => $pushUuid];

        $token = self::authApiToken();
        $url = $config->string('push_relay_uri').'/push/delete';
        try {
            [$status] = self::request('POST', $url, [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
                'Authorization' => "Bearer {$token}",
            ], Json::encode($data));
        } catch (RuntimeException $error) {
            throw ApiError::message('Req', logMessage: $error->getMessage());
        }
        if ($status >= 400) {
            throw ApiError::message('An error occurred during device unregistration: '.self::statusError($status, $url));
        }
    }

    /**
     * push_cipher_update: not for organization ciphers, like upstream.
     */
    public static function cipherUpdate(UpdateType $type, Cipher $cipher, Device $device): void
    {
        if ($cipher->organization_uuid !== null) {
            return;
        }
        if ($cipher->user_uuid === null) {
            logger()->debug('Cipher has no uuid');

            return;
        }

        if (Device::checkUserHasPushDevice($cipher->user_uuid)) {
            self::sendToPushRelay([
                'userId' => $cipher->user_uuid,
                'organizationId' => null,
                'deviceId' => $device->push_uuid,
                'identifier' => $device->uuid,
                'type' => $type->value,
                'payload' => [
                    'id' => $cipher->uuid,
                    'userId' => $cipher->user_uuid,
                    'organizationId' => null,
                    'collectionIds' => null,
                    'revisionDate' => Dates::format($cipher->updated_at),
                ],
                'clientType' => null,
                'installationId' => null,
            ]);
        }
    }

    /**
     * push_logout
     */
    public static function logout(User $user, ?Device $actingDevice): void
    {
        if (Device::checkUserHasPushDevice($user->uuid)) {
            self::logoutToRelay($user, $actingDevice);
        }
    }

    /**
     * push_logout_to_relay: without checking for push devices first, which
     * are gone once the user is deleted.
     */
    public static function logoutToRelay(User $user, ?Device $actingDevice): void
    {
        self::spawn([
            'userId' => $user->uuid,
            'organizationId' => null,
            'deviceId' => $actingDevice?->push_uuid,
            'identifier' => $actingDevice?->uuid,
            'type' => UpdateType::LogOut->value,
            'payload' => [
                'userId' => $user->uuid,
                'date' => Dates::format($user->updated_at),
            ],
            'clientType' => null,
            'installationId' => null,
        ]);
    }

    /**
     * push_user_update
     */
    public static function userUpdate(UpdateType $type, User $user, ?string $pushUuid): void
    {
        if (Device::checkUserHasPushDevice($user->uuid)) {
            self::spawn([
                'userId' => $user->uuid,
                'organizationId' => null,
                'deviceId' => $pushUuid,
                'identifier' => null,
                'type' => $type->value,
                'payload' => [
                    'userId' => $user->uuid,
                    'date' => Dates::format($user->updated_at),
                ],
                'clientType' => null,
                'installationId' => null,
            ]);
        }
    }

    /**
     * push_folder_update
     */
    public static function folderUpdate(UpdateType $type, Folder $folder, Device $device): void
    {
        if (Device::checkUserHasPushDevice($folder->user_uuid)) {
            self::spawn([
                'userId' => $folder->user_uuid,
                'organizationId' => null,
                'deviceId' => $device->push_uuid,
                'identifier' => $device->uuid,
                'type' => $type->value,
                'payload' => [
                    'id' => $folder->uuid,
                    'userId' => $folder->user_uuid,
                    'revisionDate' => Dates::format($folder->updated_at),
                ],
                'clientType' => null,
                'installationId' => null,
            ]);
        }
    }

    /**
     * push_send_update
     */
    public static function sendUpdate(UpdateType $type, Send $send, Device $device): void
    {
        if ($send->user_uuid !== null && Device::checkUserHasPushDevice($send->user_uuid)) {
            self::spawn([
                'userId' => $send->user_uuid,
                'organizationId' => null,
                'deviceId' => $device->push_uuid,
                'identifier' => $device->uuid,
                'type' => $type->value,
                'payload' => [
                    'id' => $send->uuid,
                    'userId' => $send->user_uuid,
                    'revisionDate' => Dates::format($send->revision_date),
                ],
                'clientType' => null,
                'installationId' => null,
            ]);
        }
    }

    /**
     * push_auth_request
     */
    public static function authRequest(string $userId, string $authRequestId, Device $device): void
    {
        self::authRequestNotification(UpdateType::AuthRequest, $userId, $authRequestId, $device);
    }

    /**
     * push_auth_response
     */
    public static function authResponse(string $userId, string $authRequestId, Device $device): void
    {
        self::authRequestNotification(UpdateType::AuthRequestResponse, $userId, $authRequestId, $device);
    }

    private static function authRequestNotification(UpdateType $type, string $userId, string $authRequestId, Device $device): void
    {
        if (Device::checkUserHasPushDevice($userId)) {
            self::spawn([
                'userId' => $userId,
                'organizationId' => null,
                'deviceId' => $device->push_uuid,
                'identifier' => $device->uuid,
                'type' => $type->value,
                'payload' => [
                    'userId' => $userId,
                    'id' => $authRequestId,
                ],
                'clientType' => null,
                'installationId' => null,
            ]);
        }
    }

    /**
     * tokio::task::spawn(send_to_push_relay(...)): once the response is sent.
     *
     * @param  array<string, mixed>  $notification
     */
    private static function spawn(array $notification): void
    {
        app(Deferred::class)->add(static fn () => self::sendToPushRelay($notification));
    }

    /**
     * send_to_push_relay: failures are only logged.
     *
     * @param  array<string, mixed>  $notification
     */
    private static function sendToPushRelay(array $notification): void
    {
        $config = app(Config::class);
        if (! $config->bool('push_enabled')) {
            return;
        }

        try {
            $token = self::authApiToken();
        } catch (ApiError $error) {
            logger()->debug("Could not get the auth push token: {$error->displayText()}");

            return;
        }

        try {
            self::request('POST', $config->string('push_relay_uri').'/push/send', [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'Authorization' => "Bearer {$token}",
            ], Json::encode(Json::sorted($notification)));
        } catch (ApiError|RuntimeException $error) {
            $message = $error instanceof ApiError ? $error->displayText() : $error->getMessage();
            logger()->error("An error occurred while sending a send update to the push relay: {$message}");
        }
    }

    /**
     * make_http_request(...)?.send(): a blocked host fails with Vaultwarden's
     * error, a failed request with reqwest's.
     *
     * @param  array<string, string>  $headers
     * @return array{int, string}
     *
     * @throws ApiError
     * @throws RuntimeException
     */
    private static function request(string $method, string $url, array $headers, ?string $body = null): array
    {
        try {
            [$status, $response] = HttpClient::send($method, $url, $headers, $body);
        } catch (ApiError $error) {
            if ($error->getMessage() !== 'Error sending request') {
                throw $error;
            }

            throw new RuntimeException("error sending request for url ({$url})", previous: $error);
        }

        return [$status, $response];
    }

    /**
     * reqwest's error_for_status message.
     */
    private static function statusError(int $status, string $url): string
    {
        $kind = $status >= 500 ? 'server' : 'client';
        $reason = Response::$statusTexts[$status] ?? '<unknown status code>';

        return "HTTP status {$kind} error ({$status} {$reason}) for url ({$url})";
    }
}
