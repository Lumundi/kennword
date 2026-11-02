<?php

namespace Tests\Differential;

use Tests\Attributes\Parity;
use Tests\Support\MessagePackDecoder;
use Tests\Support\WebSocketClient;

/**
 * src/api/notifications.rs on both servers: the answers of the hubs and the
 * updates they send while a user works; and src/api/push.rs: what goes to
 * the push relay. Our hubs are served by the notifications daemon.
 */
class NotificationsTest extends DifferentialTestCase
{
    #[Parity('route:GET /notifications/hub')]
    #[Parity('config:ENABLE_WEBSOCKET')]
    public function test_hub(): void
    {
        $this->assertSameNotificationFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, 'hub@example.com');
            $token = substr($auth['Authorization'], strlen('Bearer '));
            $url = (string) $server->notificationsUrl;
            $steps = [];

            $steps['plain request'] = DifferentialTestCase::send($url, 'GET', '/notifications/hub');
            $steps['plain request for JSON'] = DifferentialTestCase::send($url, 'GET', '/notifications/hub', ['Accept' => 'application/json']);
            $steps['plain request with a token'] = DifferentialTestCase::send($url, 'GET', "/notifications/hub?access_token={$token}");
            $steps['without token'] = self::answer($server->hub('/notifications/hub'));
            $steps['with a bad token'] = self::answer($server->hub('/notifications/hub?access_token=nope'));
            $steps['with an empty token'] = self::answer($server->hub('/notifications/hub?access_token='));
            $steps['with a bad header token'] = self::answer($server->hub('/notifications/hub', ['Authorization' => 'Bearer nope']));
            $steps['query before header'] = self::answer($server->hub('/notifications/hub?access_token=nope', ['Authorization' => "Bearer {$token}"]));
            $steps['WebSocket version 8'] = self::answer($server->hub("/notifications/hub?access_token={$token}", ['Sec-WebSocket-Version' => '8']));
            $steps['without key'] = self::answer($server->hub("/notifications/hub?access_token={$token}", ['Sec-WebSocket-Key' => null]));
            $steps['upgrade among other tokens'] = self::answer($server->hub("/notifications/hub?access_token={$token}",
                ['Connection' => 'keep-alive, Upgrade', 'Upgrade' => 'WebSocket']), close: true);

            $hub = $server->hub("/notifications/hub?access_token={$token}");
            $steps['upgrade'] = self::answer($hub);
            $steps['first frame'] = self::frame($hub->receive());
            $hub->handshake();
            $steps['handshake'] = self::frame($hub->receive());
            $hub->send(WebSocketClient::TEXT, '{"protocol":"json","version":1}'."\x1e");
            $hub->send(WebSocketClient::PING, 'ping');
            $steps['pong'] = self::frame($hub->receive());
            $hub->send(WebSocketClient::BINARY, 'echo');
            $steps['echo'] = self::frame($hub->receive());
            $hub->send(WebSocketClient::TEXT, 'fragmented ', fin: false);
            $hub->send(0x0, 'echo');
            $hub->send(WebSocketClient::BINARY, 'after the fragments');
            $steps['after fragments'] = self::frame($hub->receive());
            $hub->send(WebSocketClient::CLOSE, "\x03\xE8");
            $steps['after close'] = self::frame($hub->receive(3.0));

            $unmasked = $server->hub('/notifications/hub', ['Authorization' => "Bearer {$token}"]);
            $steps['token in the header'] = self::answer($unmasked);
            $unmasked->receive();
            $unmasked->send(WebSocketClient::BINARY, 'unmasked', masked: false);
            $steps['after an unmasked frame'] = self::frame($unmasked->receive(3.0));

            return $steps;
        });
    }

    #[Parity('route:GET /notifications/anonymous-hub')]
    public function test_anonymous_hub(): void
    {
        $this->assertSameNotificationFlows(function (Server $server): array {
            $email = 'anonymous-hub@example.com';
            [$auth] = CipherTest::session($server, $email);
            $token = substr($auth['Authorization'], strlen('Bearer '));
            $steps = [];

            $steps['plain request'] = DifferentialTestCase::send((string) $server->notificationsUrl, 'GET', '/notifications/anonymous-hub?token=x');
            $steps['without token'] = self::answer($server->hub('/notifications/anonymous-hub'));
            $steps['empty query'] = self::answer($server->hub('/notifications/anonymous-hub?'));
            $steps['token of another name'] = self::answer($server->hub('/notifications/anonymous-hub?id=x'), close: true);

            // A new device asks the logged-in one for the key and waits on the anonymous hub.
            $newDevice = '0d8f2c1e-3b4a-4c5d-9e6f-7a8b9c0d1e2f';
            $server->form('/identity/connect/token', ['grant_type' => 'password', 'username' => $email, 'password' => 'client-hash',
                'scope' => 'api offline_access', 'client_id' => 'web', 'device_identifier' => $newDevice, 'device_name' => 'firefox', 'device_type' => '10']);
            $hub = $server->hub("/notifications/hub?access_token={$token}");
            $hub->handshake();
            $hub->drain(0.3);

            $request = ['accessCode' => 'access-code', 'deviceIdentifier' => $newDevice, 'email' => $email, 'publicKey' => 'device-public-key', 'type' => 0];
            $steps['ask'] = $asked = $server->json('POST', '/api/auth-requests', $request, ['Accept' => 'application/json', 'Device-Type' => '10']);
            $id = $asked->jsonString('id');
            $steps['ask (updates)'] = self::updates($hub);
            $waiting = $server->hub("/notifications/anonymous-hub?token={$id}");
            $steps['wait'] = self::answer($waiting);
            $waiting->handshake();
            $waiting->drain(0.3);
            $again = $server->hub("/notifications/anonymous-hub?token={$id}");
            $again->drain(0.3);

            $steps['approve'] = $server->json('PUT', "/api/auth-requests/{$id}",
                ['deviceIdentifier' => LoginTest::DEVICE, 'key' => '4.encrypted-user-key', 'masterPasswordHash' => null, 'requestApproved' => true], $auth);
            $steps['approve (updates)'] = self::updates($hub);
            $steps['approve (anonymous updates)'] = self::updates($waiting);
            $steps['approve (anonymous updates of a reconnect)'] = self::updates($again);
            foreach ([$hub, $waiting, $again] as $connection) {
                $connection->close();
            }

            return $steps;
        });
    }

    #[Parity('route:GET /notifications/anonymous-hub')]
    public function test_anonymous_connections_per_address(): void
    {
        $this->assertSameNotificationFlows(function (Server $server): array {
            // Earlier tests closed theirs; let the server notice.
            usleep(500_000);
            $connections = [];
            $steps = [];
            for ($i = 0; $i < 25; $i++) {
                $connections[] = $connection = $server->hub("/notifications/anonymous-hub?token=limit-{$i}");
                if ($connection->status !== 101) {
                    $steps["connection {$i}"] = self::answer($connection);
                }
            }
            $steps['one too many'] = self::answer($server->hub('/notifications/anonymous-hub?token=limit-more'));
            $connections[0]->close();
            usleep(500_000);
            $steps['after one closed'] = self::answer($server->hub('/notifications/anonymous-hub?token=limit-more'), close: true);
            foreach ($connections as $connection) {
                $connection->close();
            }

            return $steps;
        });
    }

    #[Parity('route:POST /api/folders')]
    #[Parity('route:PUT /api/folders/{folder_id}')]
    #[Parity('route:DELETE /api/folders/{folder_id}')]
    #[Parity('route:POST /api/ciphers')]
    #[Parity('route:PUT /api/ciphers/{cipher_id}')]
    #[Parity('route:POST /api/ciphers/import')]
    #[Parity('route:POST /api/ciphers/purge')]
    #[Parity('route:POST /api/sends')]
    #[Parity('route:POST /api/settings/domains')]
    #[Parity('route:POST /api/accounts/security-stamp')]
    public function test_updates_of_a_personal_vault(): void
    {
        $this->assertSameNotificationFlows(function (Server $server): array {
            [$auth, $userId] = CipherTest::session($server, 'updates@example.com');
            $hub = $server->hub('/notifications/hub?access_token='.substr($auth['Authorization'], strlen('Bearer ')));
            $hub->handshake();
            $hub->drain(0.3);
            $steps = [];
            $step = static function (string $name, Exchange $exchange) use (&$steps, $hub): Exchange {
                $steps[$name] = $exchange;
                $steps["{$name} (updates)"] = self::updates($hub);

                return $exchange;
            };

            $folder = $step('create folder', $server->json('POST', '/api/folders', ['name' => '2.folder'], $auth))->jsonString('id');
            $step('rename folder', $server->json('PUT', "/api/folders/{$folder}", ['name' => '2.renamed'], $auth));
            $step('delete folder', $server->send('DELETE', "/api/folders/{$folder}", $auth));

            $note = OrganizationTest::note($userId, '2.note');
            $id = $step('create cipher', $server->json('POST', '/api/ciphers', $note, $auth))->jsonString('id');
            $second = $server->json('POST', '/api/ciphers', OrganizationTest::note($userId, '2.second'), $auth)->jsonString('id');
            $hub->drain(0.3);
            $step('update cipher', $server->json('PUT', "/api/ciphers/{$id}", $note, $auth));
            $step('partial update', $server->json('PUT', "/api/ciphers/{$id}/partial", ['folderId' => null, 'favorite' => true], $auth));
            $step('archive', $server->send('PUT', "/api/ciphers/{$id}/archive", $auth));
            $step('unarchive', $server->send('PUT', "/api/ciphers/{$id}/unarchive", $auth));
            $step('archive several', $server->json('PUT', '/api/ciphers/archive', ['ids' => [$id]], $auth));
            $step('unarchive several', $server->json('PUT', '/api/ciphers/unarchive', ['ids' => [$id]], $auth));
            $step('move one', $server->json('POST', '/api/ciphers/move', ['ids' => [$id], 'folderId' => null], $auth));
            $step('move several', $server->json('POST', '/api/ciphers/move', ['ids' => [$id, $second], 'folderId' => null], $auth));
            $step('soft delete', $server->send('PUT', "/api/ciphers/{$id}/delete", $auth));
            $step('restore', $server->send('PUT', "/api/ciphers/{$id}/restore", $auth));
            $step('soft delete several', $server->json('PUT', '/api/ciphers/delete', ['ids' => [$id]], $auth));
            $step('restore several', $server->json('PUT', '/api/ciphers/restore', ['ids' => [$id]], $auth));

            $attachment = $step('reserve attachment', $server->json('POST', "/api/ciphers/{$id}/attachment/v2", ['key' => '2.key', 'fileName' => '2.name', 'fileSize' => 11], $auth))
                ->jsonString('attachmentId');
            $step('upload attachment', $server->multipart("/api/ciphers/{$id}/attachment/{$attachment}", [['data', 'hello world', 'ignored']], $auth));
            $step('upload attachment v1', $server->multipart("/api/ciphers/{$id}/attachment", [['key', '2.key'], ['data', 'hello', '2.v1']], $auth));
            $step('delete attachment', $server->send('DELETE', "/api/ciphers/{$id}/attachment/{$attachment}", $auth));

            $step('delete cipher', $server->send('DELETE', "/api/ciphers/{$id}", $auth));
            $step('delete several', $server->json('DELETE', '/api/ciphers', ['ids' => [$second]], $auth));
            $step('import', $server->json('POST', '/api/ciphers/import', ['ciphers' => [$note], 'folders' => [['name' => '2.imported']],
                'folderRelationships' => [['key' => 0, 'value' => 0]]], $auth));

            $send = $step('create send', $server->json('POST', '/api/sends', SendTest::text(['password' => 'pw']), $auth));
            $sendId = $send->jsonString('id');
            $step('update send', $server->json('PUT', "/api/sends/{$sendId}", SendTest::text(['name' => '2.renamed']), $auth));
            $step('remove send password', $server->send('PUT', "/api/sends/{$sendId}/remove-password", $auth));
            $access = $server->form('/identity/connect/token', ['grant_type' => 'send_access', 'client_id' => 'send', 'send_id' => $send->jsonString('accessId')]);
            $step('access send', $server->send('POST', '/api/sends/access', ['Authorization' => 'Bearer '.$access->jsonString('access_token')]));
            $step('delete send', $server->send('DELETE', "/api/sends/{$sendId}", $auth));

            $step('equivalent domains', $server->json('POST', '/api/settings/domains', ['equivalentDomains' => [['example.com', 'example.net']],
                'excludedGlobalEquivalentDomains' => []], $auth));
            $step('purge', $server->json('POST', '/api/ciphers/purge', ['masterPasswordHash' => 'client-hash'], $auth));
            $step('new security stamp', $server->json('POST', '/api/accounts/security-stamp', ['masterPasswordHash' => 'client-hash'], $auth));
            $hub->close();

            return $steps;
        });
    }

    /**
     * Vaultwarden e056359a: deleting the account signs its clients out.
     */
    #[Parity('route:DELETE /api/accounts')]
    public function test_a_deleted_account_is_signed_out(): void
    {
        $this->assertSameNotificationFlows(function (Server $server): array {
            [$auth] = CipherTest::session($server, 'updates-deleted@example.com');
            $hub = $server->hub('/notifications/hub?access_token='.substr($auth['Authorization'], strlen('Bearer ')));
            $hub->handshake();
            $hub->drain(0.3);
            $steps = [];

            $steps['delete account'] = $server->json('DELETE', '/api/accounts', ['masterPasswordHash' => 'client-hash'], $auth);
            $steps['delete account (updates)'] = self::updates($hub);
            $hub->close();

            return $steps;
        });
    }

    #[Parity('route:POST /api/ciphers/create')]
    #[Parity('route:PUT /api/ciphers/{cipher_id}/collections_v2')]
    #[Parity('route:PUT /api/ciphers/{cipher_id}/share')]
    #[Parity('route:PUT /api/ciphers/share')]
    #[Parity('route:POST /api/organizations/{org_id}/users/{member_id}/confirm')]
    #[Parity('route:DELETE /api/organizations/{org_id}/users/{member_id}')]
    public function test_updates_of_an_organization(): void
    {
        $this->assertSameNotificationFlows(function (Server $server): array {
            [$owner, $ownerId] = CipherTest::session($server, 'updates-owner@example.com');
            [$member] = CipherTest::session($server, 'updates-member@example.com');
            $ownerHub = $server->hub('/notifications/hub?access_token='.substr($owner['Authorization'], strlen('Bearer ')));
            $memberHub = $server->hub('/notifications/hub?access_token='.substr($member['Authorization'], strlen('Bearer ')));
            $org = $server->json('POST', '/api/organizations', OrganizationTest::org(), $owner)->jsonString('id');
            $collection = $server->send('GET', "/api/organizations/{$org}/collections", $owner)->jsonString('data.0.id');
            foreach ([$ownerHub, $memberHub] as $hub) {
                $hub->handshake();
                $hub->drain(0.3);
            }
            $steps = [];
            $step = static function (string $name, Exchange $exchange) use (&$steps, $ownerHub, $memberHub): Exchange {
                $steps[$name] = $exchange;
                $steps["{$name} (owner's updates)"] = self::updates($ownerHub);
                $steps["{$name} (member's updates)"] = self::updates($memberHub, first: 0.2);

                return $exchange;
            };

            $memberId = OrganizationTest::addMember($server, $owner, $org, 'updates-member@example.com');
            $steps['confirm (owner\'s updates)'] = self::updates($ownerHub);
            $steps['confirm (member\'s updates)'] = self::updates($memberHub);

            $id = $step('create', $server->json('POST', '/api/ciphers/create', ['cipher' => OrganizationTest::note($ownerId, '2.shared',
                ['organizationId' => $org]), 'collectionIds' => [$collection]], $owner))->jsonString('id');
            $step('update', $server->json('PUT', "/api/ciphers/{$id}", OrganizationTest::note($ownerId, '2.shared', ['organizationId' => $org]), $owner));
            $step('collections', $server->json('PUT', "/api/ciphers/{$id}/collections_v2", ['collectionIds' => [$collection]], $owner));
            $personal = $server->json('POST', '/api/ciphers', OrganizationTest::note($ownerId, '2.personal'), $owner)->jsonString('id');
            $ownerHub->drain(0.3);
            $step('share', $server->json('PUT', "/api/ciphers/{$personal}/share", ['cipher' => OrganizationTest::note($ownerId, '2.personal',
                ['organizationId' => $org]), 'collectionIds' => [$collection]], $owner));
            $more = $server->json('POST', '/api/ciphers', OrganizationTest::note($ownerId, '2.more'), $owner)->jsonString('id');
            $ownerHub->drain(0.3);
            $step('share several', $server->json('PUT', '/api/ciphers/share', ['ciphers' => [[...OrganizationTest::note($ownerId, '2.more',
                ['organizationId' => $org]), 'id' => $more]], 'collectionIds' => [$collection]], $owner));
            $step('delete', $server->send('DELETE', "/api/ciphers/{$id}", $owner));
            $step('remove member', $server->send('DELETE', "/api/organizations/{$org}/users/{$memberId}", $owner));
            $ownerHub->close();
            $memberHub->close();

            return $steps;
        });
    }

    #[Parity('config:PUSH_*')]
    #[Parity('route:PUT /api/devices/identifier/{device_id}/token')]
    #[Parity('route:PUT /api/devices/identifier/{device_id}/clear-token')]
    public function test_push(): void
    {
        $this->assertSamePushFlows(function (Server $server): array {
            $email = 'push-phone@example.com';
            LoginTest::register($server, $email);
            $phone = '5d2c0f4e-8a1b-4c3d-9e7f-6a5b4c3d2e1f';
            $login = ['grant_type' => 'password', 'username' => $email, 'password' => 'client-hash', 'scope' => 'api offline_access',
                'client_id' => 'mobile', 'device_identifier' => $phone, 'device_name' => 'Pixel', 'device_type' => '0'];
            $auth = ['Authorization' => 'Bearer '.$server->form('/identity/connect/token', $login)->jsonString('access_token'), 'Accept' => 'application/json'];
            $userId = $server->send('GET', '/api/accounts/profile', $auth)->jsonString('id');
            $steps = [];
            $step = static function (string $name, Exchange $exchange) use (&$steps, $server): Exchange {
                $before = count($server->relayed());
                $steps[$name] = $exchange;
                $steps["{$name} (pushed)"] = self::relayedSince($server, $before);

                return $exchange;
            };
            $step('push token', $server->json('PUT', "/api/devices/identifier/{$phone}/token", ['pushToken' => 'fcm-token'], $auth));
            $step('same push token', $server->json('PUT', "/api/devices/identifier/{$phone}/token", ['pushToken' => 'fcm-token'], $auth));
            $step('login again', $server->form('/identity/connect/token', $login));
            $folder = $step('create folder', $server->json('POST', '/api/folders', ['name' => '2.folder'], $auth))->jsonString('id');
            $step('delete folder', $server->send('DELETE', "/api/folders/{$folder}", $auth));
            $id = $step('create cipher', $server->json('POST', '/api/ciphers', OrganizationTest::note($userId, '2.note'), $auth))->jsonString('id');
            $step('delete cipher', $server->send('DELETE', "/api/ciphers/{$id}", $auth));
            $step('create send', $server->json('POST', '/api/sends', SendTest::text(), $auth));
            $step('equivalent domains', $server->json('POST', '/api/settings/domains', ['equivalentDomains' => [], 'excludedGlobalEquivalentDomains' => []], $auth));
            $step('clear push token', $server->send('PUT', "/api/devices/identifier/{$phone}/clear-token"));
            $step('create folder without token', $server->json('POST', '/api/folders', ['name' => '2.folder'], $auth));
            // Vaultwarden e056359a: the logout reaches the relay after the devices are gone.
            $step('push token again', $server->json('PUT', "/api/devices/identifier/{$phone}/token", ['pushToken' => 'fcm-token'], $auth));
            $step('delete account', $server->json('DELETE', '/api/accounts', ['masterPasswordHash' => 'client-hash'], $auth));

            return $steps;
        });
    }

    /**
     * The answer to an upgrade request.
     */
    private static function answer(WebSocketClient $client, bool $close = false): Exchange
    {
        if ($close) {
            $client->close();
        }

        return new Exchange($client->status, $client->headers, $client->body);
    }

    /**
     * A frame the client received, null once the server closed the connection.
     *
     * @param  array{int, string}|null  $frame
     */
    private static function frame(?array $frame): Exchange
    {
        return new Exchange(200, ['content-type' => 'application/json'], (string) json_encode(
            $frame === null ? null : ['opcode' => $frame[0], 'payload' => bin2hex($frame[1])],
        ));
    }

    /**
     * The updates a hub received since the last step, decoded.
     */
    private static function updates(WebSocketClient $hub, float $first = 0.6): Exchange
    {
        $messages = [];
        foreach ($hub->drain($first) as $frame) {
            array_push($messages, ...MessagePackDecoder::signalR($frame));
        }

        return new Exchange(200, ['content-type' => 'application/json'], (string) json_encode($messages, JSON_UNESCAPED_SLASHES));
    }

    /**
     * What the server's push relay received after the first requests, once
     * nothing more arrives (Vaultwarden pushes from spawned tasks), in a fixed
     * order.
     */
    private static function relayedSince(Server $server, int $count): Exchange
    {
        $relayed = [];
        $deadline = microtime(true) + 5;
        do {
            $previous = $relayed;
            usleep(400_000);
            $relayed = array_slice($server->relayed(), $count);
        } while (count($relayed) !== count($previous) && microtime(true) < $deadline);

        $encoded = array_map(static fn (mixed $request): string => (string) json_encode($request, JSON_UNESCAPED_SLASHES), $relayed);
        sort($encoded);

        return new Exchange(200, ['content-type' => 'application/json'], '['.implode(',', $encoded).']');
    }
}
