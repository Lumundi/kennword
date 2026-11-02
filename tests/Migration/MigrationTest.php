<?php

namespace Tests\Migration;

use App\Http\Controllers\TwoFactor\AuthenticatorController;
use App\Support\Base32;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use stdClass;
use Tests\Differential\Exchange;
use Tests\Differential\LoginTest;
use Tests\Differential\Server;
use Tests\Differential\TwoFactorTest;
use Tests\Support\SoftwareAuthenticator;

/**
 * An installation moves from Vaultwarden to this implementation and back
 * (.github/scripts/migration.sh). Vaultwarden fills it through its API with
 * every kind of data; after vaultwarden:migrate we read it all back from the
 * same database and data folder and change it; then Vaultwarden starts on
 * the result and reads our changes. Each phase runs on its own against
 * VW_MIGRATION_URL (VW_MIGRATION_PHASE is fill, move or back) and first
 * compares what it sees with what the phase before saw last. The servers
 * share the port, the key file and the mail sink (VW_MIGRATION_MAIL_DIR),
 * so even their links and tokens carry over.
 */
class MigrationTest extends TestCase
{
    private const string RANGE = 'start=2000-01-01T00:00:00.000Z&end=2100-01-01T00:00:00.000Z';

    // The second device of the member, which approves login requests.
    private const string BROWSER = 'b7c1d2e3-f4a5-4b6c-8d7e-9f0a1b2c3d4e';

    private Server $server;

    private Installation $installation;

    protected function setUp(): void
    {
        foreach (['VW_MIGRATION_URL', 'VW_MIGRATION_PHASE', 'VW_MIGRATION_STATE', 'VW_MIGRATION_MAIL_DIR'] as $name) {
            if (! getenv($name)) {
                $this->markTestSkipped('Run .github/scripts/migration.sh to move an installation.');
            }
        }
        $this->server = new Server((string) getenv('VW_MIGRATION_URL'), (string) getenv('VW_MIGRATION_MAIL_DIR'));
        $this->installation = Installation::open((string) getenv('VW_MIGRATION_STATE'));
    }

    protected function tearDown(): void
    {
        if (isset($this->installation)) {
            $this->installation->save();
        }
    }

    public function test_the_installation_moves(): void
    {
        match (getenv('VW_MIGRATION_PHASE')) {
            'fill' => $this->fill(),
            'move' => $this->move(),
            'back' => $this->back(),
            default => throw new RuntimeException('VW_MIGRATION_PHASE is fill, move or back.'),
        };
    }

    /**
     * Vaultwarden: every kind of data its clients can store.
     */
    private function fill(): void
    {
        // Users with each kind of KDF settings.
        $this->register('owner', ['kdf' => 0, 'kdfIterations' => 600000]);
        $this->register('member', ['kdf' => 0, 'kdfIterations' => 350000]);
        $this->register('argon', ['kdf' => 1, 'kdfIterations' => 3, 'kdfMemory' => 64, 'kdfParallelism' => 4]);

        // Folders and ciphers of every type, with what they may hold.
        $work = $this->ok($this->post('owner', '/api/folders', ['name' => '2.work']))->jsonString('id');
        $home = $this->ok($this->post('owner', '/api/folders', ['name' => '2.home']))->jsonString('id');
        $this->ok($this->post('member', '/api/folders', ['name' => '2.member-folder']));
        $login = $this->cipher('owner', 1, '2.login', [
            'folderId' => $work, 'favorite' => true, 'reprompt' => 1, 'notes' => '2.notes',
            'fields' => [['name' => '2.text', 'value' => '2.value', 'type' => 0], ['name' => '2.hidden', 'value' => '2.secret', 'type' => 1],
                ['name' => '2.boolean', 'value' => 'true', 'type' => 2], ['name' => '2.linked', 'type' => 3, 'linkedId' => 100]],
            'passwordHistory' => [['password' => '2.old', 'lastUsedDate' => '2026-01-02T03:04:05.123Z']],
            'login' => ['username' => '2.user', 'password' => '2.pass', 'passwordRevisionDate' => '2026-03-04T05:06:07.100Z', 'totp' => '2.totp',
                'uris' => [['uri' => '2.uri', 'match' => 0, 'uriChecksum' => '2.checksum'], ['uri' => '2.other', 'match' => null]],
                'fido2Credentials' => [['credentialId' => '2.cred', 'keyType' => '2.public-key', 'keyAlgorithm' => '2.ECDSA', 'keyCurve' => '2.P-256',
                    'keyValue' => '2.key', 'rpId' => '2.example.com', 'userHandle' => '2.handle', 'userName' => '2.name', 'counter' => '2.0',
                    'rpName' => '2.rp', 'userDisplayName' => '2.display', 'discoverable' => '2.true', 'creationDate' => '2026-05-06T07:08:09.000Z']]],
        ]);
        $note = $this->cipher('owner', 2, '2.note', ['secureNote' => ['type' => 0], 'favorite' => true]);
        $card = $this->cipher('owner', 3, '2.card', ['folderId' => $home,
            'card' => ['cardholderName' => '2.h', 'number' => '2.n', 'expMonth' => '2.m', 'expYear' => '2.y', 'code' => '2.c', 'brand' => '2.b']]);
        $this->cipher('owner', 4, '2.identity', ['identity' => ['title' => '2.t', 'firstName' => '2.f', 'lastName' => '2.l', 'ssn' => '2.s',
            'address1' => '2.a', 'city' => '2.c', 'postalCode' => '2.p', 'country' => '2.c', 'email' => '2.e', 'phone' => '2.p']]);
        $this->cipher('owner', 5, '2.ssh', ['sshKey' => ['privateKey' => '2.private', 'publicKey' => '2.public', 'keyFingerprint' => '2.fingerprint']]);
        $trashed = $this->cipher('owner', 1, '2.trashed', ['login' => ['username' => '2.gone']]);
        $this->cipher('member', 2, '2.member-note', ['secureNote' => ['type' => 0]]);
        $this->ok($this->put('owner', "/api/ciphers/{$note}/archive"));
        $this->ok($this->put('owner', "/api/ciphers/{$trashed}/delete"));
        foreach (['login' => $login, 'note' => $note, 'card' => $card, 'trashed' => $trashed] as $name => $id) {
            $this->installation->set("cipher.{$name}", $id);
        }

        // Attachments, uploaded the current way and the old one.
        $this->attachment('owner', $login, 'attachment of a login');
        $legacy = $this->ok($this->server->multipart("/api/ciphers/{$card}/attachment", [['key', '2.legacy-key'], ['data', 'legacy attachment', '2.iv/legacy|name+/==']],
            $this->installation->auth('owner')));
        $this->installation->push('attachments', ['owner', $card, $legacy->jsonString('attachments.0.id')]);
        $this->ok($this->post('owner', '/api/settings/domains', ['equivalentDomains' => [['example.com', 'example.net']], 'excludedGlobalEquivalentDomains' => [2, 3]]));

        // An organization with collections, groups, policies and an API key.
        $org = $this->ok($this->post('owner', '/api/organizations', ['billingEmail' => 'billing@example.com', 'collectionName' => '2.first',
            'key' => '4.org-key', 'name' => '2.org', 'planType' => 0]))->jsonString('id');
        $this->installation->set('org', $org);
        $first = $this->ok($this->get('owner', "/api/organizations/{$org}/collections"))->jsonString('data.0.id');
        $memberId = $this->join('member', 2, [['id' => $first, 'readOnly' => true, 'hidePasswords' => false, 'manage' => false]]);
        $this->join('argon', 3, [], confirm: false);
        $this->ok($this->post('owner', "/api/organizations/{$org}/users/invite", ['emails' => ['invited@example.com'], 'groups' => [], 'type' => 2, 'collections' => []]));
        $group = $this->ok($this->post('owner', "/api/organizations/{$org}/groups", ['name' => 'Readers', 'accessAll' => false, 'externalId' => 'readers',
            'collections' => [['id' => $first, 'readOnly' => false, 'hidePasswords' => true, 'manage' => false]], 'users' => [$memberId]]))->jsonString('id');
        $second = $this->ok($this->post('owner', "/api/organizations/{$org}/collections", ['name' => '2.second', 'externalId' => 'second',
            'groups' => [['id' => $group, 'readOnly' => true, 'hidePasswords' => false, 'manage' => false]],
            'users' => [['id' => $memberId, 'readOnly' => false, 'hidePasswords' => false, 'manage' => true]]]))->jsonString('id');
        $this->installation->set('collections', [$first, $second]);
        $this->installation->set('group', $group);
        $shared = $this->ok($this->post('owner', '/api/ciphers/create', ['cipher' => ['type' => 1, 'name' => '2.shared', 'organizationId' => $org, 'encryptedFor' => $this->installation->string('owner.id'),
            'login' => ['username' => '2.team']], 'collectionIds' => [$first, $second]]))->jsonString('id');
        $this->ok($this->post('owner', '/api/ciphers/create', ['cipher' => ['type' => 2, 'name' => '2.team-note', 'organizationId' => $org, 'encryptedFor' => $this->installation->string('owner.id'),
            'secureNote' => ['type' => 0]], 'collectionIds' => [$second]]));
        $this->attachment('owner', $shared, 'attachment of an organization');
        $this->ok($this->put('owner', "/api/organizations/{$org}/policies/1", ['policy' => ['enabled' => true, 'data' => ['minComplexity' => 2, 'minLength' => 12]]]));
        $this->ok($this->put('owner', "/api/organizations/{$org}/policies/2", ['policy' => ['enabled' => true, 'data' => ['useUpper' => true, 'minLength' => 14]]]));
        $this->ok($this->put('owner', "/api/organizations/{$org}/policies/8", ['policy' => ['enabled' => true, 'data' => ['autoEnrollEnabled' => false]]]));
        // Fill Assist (Vaultwarden 1.37.5) needs the single organization policy.
        $this->ok($this->put('owner', "/api/organizations/{$org}/policies/3", ['policy' => ['enabled' => true, 'data' => null]]));
        $this->ok($this->put('owner', "/api/organizations/{$org}/policies/22", ['policy' => ['enabled' => true, 'data' => ['rulesUrl' => 'https://rules.example/feed']]]));
        $this->ok($this->put('member', "/api/organizations/{$org}/users/{$this->installation->string('member.id')}/reset-password-enrollment",
            ['resetPasswordKey' => '4.reset-key', 'masterPasswordHash' => $this->password('member')]));
        $this->installation->set('org.key', $this->ok($this->post('owner', "/api/organizations/{$org}/api-key", ['masterPasswordHash' => $this->password('owner')]))->jsonString('apiKey'));
        $this->installation->set('owner.api-key', $this->ok($this->post('owner', '/api/accounts/api-key', ['masterPasswordHash' => $this->password('owner')]))->jsonString('apiKey'));

        // Emergency access: one the member may use, one waiting for the other user.
        $view = $this->trust('member', 0, 1);
        $this->ok($this->post('member', "/api/emergency-access/{$view}/accept", ['token' => $this->server->mailedToken('member@example.com')]));
        $this->ok($this->post('owner', "/api/emergency-access/{$view}/confirm", ['key' => '4.member-emergency-key']));
        $this->ok($this->post('member', "/api/emergency-access/{$view}/initiate"));
        $this->ok($this->post('owner', "/api/emergency-access/{$view}/approve"));
        $this->installation->set('emergency.view', $view);
        $this->installation->set('emergency.takeover', $this->trust('argon', 1, 7));
        $this->installation->set('emergency.takeover.token', $this->server->mailedToken('argon@example.com'));

        // Sends, a text with a password and a file.
        $text = $this->ok($this->post('owner', '/api/sends', ['type' => 0, 'key' => '2.send-key', 'name' => '2.text-send', 'notes' => '2.send-notes',
            'text' => ['text' => '2.secret-text', 'hidden' => true], 'password' => 'send-password', 'maxAccessCount' => 20, 'hideEmail' => true,
            'expirationDate' => self::days(20), 'deletionDate' => self::days(30), 'disabled' => false]));
        $this->installation->push('sends', [$text->jsonString('accessId'), 'send-password']);
        $this->fileSend('owner', 'file of a send');

        // Two-factor login: an authenticator app, a security key and mail for the owner, an
        // authenticator app with the recovery code for argon. The owner's device remembers it.
        $this->authenticator('owner');
        $key = new SoftwareAuthenticator;
        $this->securityKey('owner', $key, 1);
        $this->installation->set('owner.webauthn', [$key->export()]);
        $verification = $this->ok($this->post('owner', '/api/two-factor/get-email', ['masterPasswordHash' => $this->password('owner')]))->jsonString('userVerificationToken');
        $address = ['email' => 'owner-2fa@example.com', 'userVerificationToken' => $verification];
        $this->ok($this->post('owner', '/api/two-factor/send-email', $address));
        $this->ok($this->put('owner', '/api/two-factor/email', [...$address, 'token' => $this->mailedCode('owner-2fa@example.com')]));
        $remembered = $this->ok($this->login('owner', ['two_factor_provider' => '0', 'two_factor_token' => $this->totp('owner'), 'two_factor_remember' => '1']));
        $this->installation->set('owner.remember', $remembered->jsonString('TwoFactorToken'));
        $this->authenticator('argon');
        $this->installation->set('argon.recovery', $this->ok($this->post('argon', '/api/two-factor/get-recover', ['masterPasswordHash' => $this->password('argon')]))->jsonString('code'));

        // Login requests of the member: one approved by its browser, one waiting.
        $this->ok($this->login('member', ['device_identifier' => self::BROWSER, 'device_name' => 'firefox', 'device_type' => '10'], 'member-browser'));
        $this->authRequest('member', approve: true);
        $this->authRequest('member', approve: false);

        // Settings saved in the admin panel, which go to config.json in the data folder.
        $login = $this->server->form('/admin', ['token' => (string) getenv('VW_MIGRATION_ADMIN_TOKEN')]);
        $this->installation->set('admin', preg_match('/VW_ADMIN=([^;]+)/', (string) $login->header('Set-Cookie'), $cookie) === 1
            ? $cookie[1] : throw new RuntimeException("No admin session in the {$login->status} response: {$login->body}"));
        $this->ok($this->admin('POST', '/admin/config', ['invitation_org_name' => 'Migration test', 'icon_cache_ttl' => 1234, 'signups_domains_whitelist' => 'example.com']));

        $this->accessSends('fill');
        $this->installation->saveViews('fill', $this->views());
    }

    /**
     * This implementation, after vaultwarden:migrate on Vaultwarden's data:
     * everything reads back the same and every way to log in works; then we
     * change the installation for Vaultwarden to read.
     */
    private function move(): void
    {
        $this->assertSameViews($this->installation->views('fill'), $this->views(), 'after the move');
        $this->accessSends('move');
        $this->logins();
        $org = $this->installation->string('org');
        $ciphers = array_map(fn (string $name): string => $this->installation->string("cipher.{$name}"), ['login' => 'login', 'note' => 'note', 'card' => 'card', 'trashed' => 'trashed']);

        // Ciphers, folders, attachments and Sends: new and changed.
        $folder = $this->ok($this->post('owner', '/api/folders', ['name' => '2.moved']))->jsonString('id');
        $new = $this->cipher('owner', 1, '2.written-here', ['folderId' => $folder, 'login' => ['username' => '2.new', 'uris' => [['uri' => '2.new-uri', 'match' => 1]]]]);
        $this->attachment('owner', $new, 'attachment written here');
        $this->ok($this->put('owner', "/api/ciphers/{$ciphers['login']}", ['type' => 1, 'name' => '2.login-renamed', 'favorite' => false, 'folderId' => $folder,
            'encryptedFor' => $this->installation->string('owner.id'),
            'login' => ['username' => '2.user', 'password' => '2.changed']]));
        $this->ok($this->put('owner', "/api/ciphers/{$ciphers['trashed']}/restore"));
        $this->ok($this->put('owner', "/api/ciphers/{$ciphers['note']}/unarchive"));
        $this->ok($this->put('owner', "/api/ciphers/{$ciphers['card']}/archive"));
        $this->ok($this->post('owner', '/api/settings/domains', ['equivalentDomains' => [['example.org', 'example.net']], 'excludedGlobalEquivalentDomains' => [4]]));
        $this->fileSend('owner', 'file of a send written here');
        $text = $this->ok($this->post('owner', '/api/sends', ['type' => 0, 'key' => '2.key', 'name' => '2.written-here', 'text' => ['text' => '2.t', 'hidden' => false],
            'deletionDate' => self::days(30), 'disabled' => false]));
        $this->installation->push('sends', [$text->jsonString('accessId'), null]);

        // The organization: a new collection, changed access and policies, a confirmed member, a new key.
        $third = $this->ok($this->post('owner', "/api/organizations/{$org}/collections", ['name' => '2.third', 'groups' => [], 'users' => []]))->jsonString('id');
        $argon = $this->memberId('argon');
        $this->ok($this->post('owner', "/api/organizations/{$org}/users/{$argon}/confirm", ['key' => '4.argon-org-key']));
        $this->ok($this->put('owner', "/api/organizations/{$org}/users/{$argon}", ['type' => 1, 'collections' => [['id' => $third, 'readOnly' => false, 'hidePasswords' => false, 'manage' => true]]]));
        $this->ok($this->put('owner', "/api/organizations/{$org}/groups/{$this->installation->string('group')}", ['name' => 'Readers and writers', 'accessAll' => false,
            'collections' => [['id' => $third, 'readOnly' => true, 'hidePasswords' => true, 'manage' => false]], 'users' => [$this->memberId('member'), $argon]]));
        $this->ok($this->put('owner', "/api/organizations/{$org}/policies/2", ['policy' => ['enabled' => false, 'data' => null]]));
        $this->ok($this->put('owner', "/api/organizations/{$org}/policies/7", ['policy' => ['enabled' => true, 'data' => ['disableHideEmail' => true]]]));
        $this->ok($this->post('owner', '/api/ciphers/create', ['cipher' => ['type' => 2, 'name' => '2.team-written-here', 'organizationId' => $org, 'encryptedFor' => $this->installation->string('owner.id'),
            'secureNote' => ['type' => 0]], 'collectionIds' => [$third]]));
        $this->installation->set('org.key', $this->ok($this->post('owner', "/api/organizations/{$org}/rotate-api-key", ['masterPasswordHash' => $this->password('owner')]))->jsonString('apiKey'));

        // Accounts: new KDF settings and password, a new API key, two-factor methods, emergency access.
        $this->changeKdf('member', ['kdf' => 1, 'kdfIterations' => 4, 'kdfMemory' => 32, 'kdfParallelism' => 2], 'member-hash-2');
        $this->ok($this->post('argon', '/api/accounts/password', ['masterPasswordHash' => $this->password('argon'), 'newMasterPasswordHash' => 'argon-hash-2', 'key' => 'argon-key-2']));
        $this->installation->set('argon.password', 'argon-hash-2');
        $this->ok($this->login('argon'));
        $this->authenticator('argon');
        $this->installation->set('owner.api-key', $this->ok($this->post('owner', '/api/accounts/rotate-api-key', ['masterPasswordHash' => $this->password('owner')]))->jsonString('apiKey'));
        $key = new SoftwareAuthenticator;
        $this->securityKey('owner', $key, 2);
        $this->installation->push('owner.webauthn', $key->export());
        $takeover = $this->installation->string('emergency.takeover');
        $this->ok($this->post('argon', "/api/emergency-access/{$takeover}/accept", ['token' => $this->installation->string('emergency.takeover.token')]));
        $this->ok($this->post('owner', "/api/emergency-access/{$takeover}/confirm", ['key' => '4.takeover-key']));
        $this->ok($this->login('member', ['device_identifier' => self::BROWSER, 'device_name' => 'firefox', 'device_type' => '10'], 'member-browser'));
        $this->authRequest('member', approve: true);

        $this->ok($this->admin('POST', '/admin/config', ['invitation_org_name' => 'Migration test, moved', 'icon_cache_ttl' => 4321, 'org_creation_users' => 'owner@example.com']));

        $this->accessSends('moved');
        $this->installation->saveViews('move', $this->views());
    }

    /**
     * Vaultwarden again, on what we left: our changes read back the same and
     * the logins we set up work.
     */
    private function back(): void
    {
        $this->assertSameViews($this->installation->views('move'), $this->views(), 'after the way back');
        $this->accessSends('back');
        $this->logins();
    }

    /**
     * Every way to log in the installation offers, each checked against the
     * answer of the phase before where it gave one.
     */
    private function logins(): void
    {
        $owner = $this->installation->string('owner.email');

        // Tokens the server before issued go on working: an access token for every
        // request of the views, the refresh token for a new one.
        $refresh = $this->ok($this->server->form('/identity/connect/token', ['grant_type' => 'refresh_token', 'client_id' => 'cli',
            'refresh_token' => $this->installation->string('member.refresh')]), 200, 'refresh');
        $this->installation->set('member.token', $refresh->jsonString('access_token'));
        $this->installation->set('member.refresh', $refresh->jsonString('refresh_token'));

        $prompt = $this->login('owner');
        $this->assertSame(400, $prompt->status, $prompt->body);
        $this->assertEqualsCanonicalizing(['0', '1', '7'], $prompt->json('TwoFactorProviders'), $prompt->body);
        $this->ok($this->login('owner', ['two_factor_provider' => '5', 'two_factor_token' => $this->installation->string('owner.remember')]), 200, 'remembered device');
        $this->ok($this->login('owner', ['two_factor_provider' => '0', 'two_factor_token' => $this->totp('owner')]), 200, 'authenticator');
        $keys = array_map(static fn (mixed $key): SoftwareAuthenticator => SoftwareAuthenticator::restore(is_array($key) ? $key : []), $this->installation->list('owner.webauthn'));
        foreach ($keys as $key) {
            $answer = $key->assert(TwoFactorTest::request($this->login('owner')));
            $this->ok($this->login('owner', ['two_factor_provider' => '7', 'two_factor_token' => $answer]), 200, 'security key');
        }
        $this->installation->set('owner.webauthn', array_map(static fn (SoftwareAuthenticator $key): array => $key->export(), $keys));
        $this->ok($this->server->json('POST', '/api/two-factor/send-email-login', ['email' => $owner, 'masterPasswordHash' => $this->password('owner')]));
        $this->ok($this->login('owner', ['two_factor_provider' => '1', 'two_factor_token' => $this->mailedCode('owner-2fa@example.com')]), 200, 'mail');

        // Argon has an authenticator app; its recovery code, made by Vaultwarden, turns two-factor login off here.
        if ($this->installation->has('argon.recovery')) {
            $recovered = $this->login('argon', ['two_factor_provider' => '8', 'two_factor_token' => $this->installation->string('argon.recovery')]);
            $this->ok($recovered, 200, 'recovery code');
            $this->installation->set('argon.recovery', null);
            $this->installation->set('argon.totp', null);
        } else {
            $this->ok($this->login('argon', ['two_factor_provider' => '0', 'two_factor_token' => $this->totp('argon')]), 200, 'authenticator of argon');
        }

        $this->ok($this->login('member'), 200, 'password');
        $this->ok($this->server->form('/identity/connect/token', ['grant_type' => 'client_credentials', 'client_id' => 'user.'.$this->installation->string('owner.id'),
            'client_secret' => $this->installation->string('owner.api-key'), 'scope' => 'api', 'device_identifier' => LoginTest::DEVICE,
            'device_name' => 'linux', 'device_type' => '25']), 200, 'personal API key');
        $this->ok($this->server->form('/identity/connect/token', ['grant_type' => 'client_credentials', 'client_id' => 'organization.'.$this->installation->string('org'),
            'client_secret' => $this->installation->string('org.key'), 'scope' => 'api.organization']), 200, 'organization API key');

        // The approved login request of the phase before, from the device that asked.
        foreach ($this->installation->records('auth-requests') as [$id, $code]) {
            $this->ok($this->login('member', ['password' => (string) $code, 'authRequest' => (string) $id]), 200, 'login request');
        }
        $this->installation->set('auth-requests', []);
    }

    /**
     * What the clients read from the installation, by name: every vault,
     * the organization, attachments with their files, emergency access,
     * login requests and two-factor methods. Values that the server makes
     * anew for each answer (tokens) are left out.
     *
     * @return array<string, string>
     */
    private function views(): array
    {
        $views = [];
        $org = $this->installation->string('org');
        foreach (['owner', 'member', 'argon'] as $user) {
            $views["{$user} sync"] = $this->get($user, '/api/sync?excludeDomains=true');
            $views["{$user} devices"] = $this->get($user, '/api/devices');
            $views["{$user} two-factor methods"] = $this->get($user, '/api/two-factor');
            $views["{$user} trusted emergency contacts"] = $this->get($user, '/api/emergency-access/trusted');
            $views["{$user} granted emergency access"] = $this->get($user, '/api/emergency-access/granted');
            $views["{$user} pending login requests"] = $this->get($user, '/api/auth-requests/pending');
            $views["{$user} revision date"] = $this->get($user, '/api/accounts/revision-date');
            $views["{$user} prelogin"] = $this->server->json('POST', '/identity/accounts/prelogin', ['email' => $this->installation->string("{$user}.email")]);
        }
        // The KDF settings of unknown users come from the key file.
        $views['unknown prelogin'] = $this->server->json('POST', '/identity/accounts/prelogin', ['email' => 'nobody@example.com']);
        $views['owner domains'] = $this->get('owner', '/api/settings/domains');
        $views['organization'] = $this->get('owner', "/api/organizations/{$org}");
        $views['organization members'] = $this->get('owner', "/api/organizations/{$org}/users?includeCollections=true&includeGroups=true");
        $views['organization collections'] = $this->get('owner', "/api/organizations/{$org}/collections/details");
        $views['organization groups'] = $this->get('owner', "/api/organizations/{$org}/groups/details");
        $views['organization policies'] = $this->get('owner', "/api/organizations/{$org}/policies");
        $views['organization ciphers'] = $this->get('owner', "/api/ciphers/organization-details?organizationId={$org}");
        $views['organization events'] = $this->events("/api/organizations/{$org}/events");
        $views['organization API key'] = $this->post('owner', "/api/organizations/{$org}/api-key", ['masterPasswordHash' => $this->password('owner')]);
        $views['member\'s emergency view'] = $this->post('member', "/api/emergency-access/{$this->installation->string('emergency.view')}/view");
        foreach ($this->installation->records('auth-request-ids') as [$id]) {
            $views["login request {$id}"] = $this->get('member', "/api/auth-requests/{$id}");
        }
        // The admin panel's overviews, and the settings it saved.
        $views['admin users'] = $this->admin('GET', '/admin/users');
        $views['admin users overview'] = self::tableRowsInOrder($this->admin('GET', '/admin/users/overview'));
        $views['admin organizations overview'] = self::tableRowsInOrder($this->admin('GET', '/admin/organizations/overview'));
        $views['admin settings'] = $this->admin('GET', '/admin/diagnostics/config');
        foreach ($this->installation->records('attachments') as [$user, $cipher, $attachment]) {
            $views["attachment {$attachment}"] = $metadata = $this->get((string) $user, "/api/ciphers/{$cipher}/attachment/{$attachment}");
            $views["file of attachment {$attachment}"] = $this->server->send('GET', (string) preg_replace('#^https?://[^/]+#', '', $metadata->jsonString('url')));
        }

        return array_map(self::view(...), $views);
    }

    /**
     * Each Send through its link, as someone without an account: the text
     * or the file, which also counts an access.
     */
    private function accessSends(string $label): void
    {
        foreach ($this->installation->records('sends') as $index => [$accessId, $password]) {
            $token = $this->server->form('/identity/connect/token', array_filter(['grant_type' => 'send_access', 'client_id' => 'send', 'send_id' => $accessId,
                'password_hash_b64' => $password]));
            $access = ['Authorization' => 'Bearer '.$this->ok($token, 200, "token of Send {$index}")->jsonString('access_token'), 'Accept' => 'application/json'];
            $send = $this->ok($this->server->send('POST', '/api/sends/access', $access), 200, "Send {$index}");
            $this->assertSameAsBefore("Send {$index}", self::view($send), $label);
            $file = $send->json('file.id');
            if (is_string($file)) {
                $url = $this->ok($this->server->send('POST', "/api/sends/access/file/{$file}", $access))->jsonString('url');
                $download = $this->server->send('GET', (string) preg_replace('#^https?://[^/]+#', '', $url));
                $this->assertSameAsBefore("file of Send {$index}", self::view($download), $label);
            }
        }
    }

    /**
     * Records an answer the first time, and asserts the same later on.
     */
    private function assertSameAsBefore(string $name, string $view, string $label): void
    {
        $key = "answers.{$name}";
        if ($this->installation->has($key)) {
            $this->assertSame($this->installation->string($key), $view, "{$name} {$label}");
        }
        $this->installation->set($key, $view);
    }

    /**
     * @param  array<string, string>  $expected
     * @param  array<string, string>  $actual
     */
    private function assertSameViews(array $expected, array $actual, string $label): void
    {
        $this->assertSame(array_keys($expected), array_keys($actual), "Views {$label}");
        // Only the views that differ, so that the diff stays readable.
        $differing = array_keys(array_diff_assoc($expected, $actual));
        $this->assertSame(array_intersect_key($expected, array_flip($differing)), array_intersect_key($actual, array_flip($differing)), "Views {$label}");
    }

    /**
     * @param  array<string, int|string>  $kdf
     */
    private function register(string $user, array $kdf): void
    {
        $email = "{$user}@example.com";
        $token = $this->server->json('POST', '/identity/accounts/register/send-verification-email', ['email' => $email], ['Accept' => 'application/json'])->json();
        $this->ok($this->server->json('POST', '/identity/accounts/register/finish', ['email' => $email, 'emailVerificationToken' => $token, ...$kdf,
            'masterPasswordHash' => 'client-hash', 'masterPasswordHint' => "hint of {$user}", 'key' => "{$user}-key",
            'keys' => ['encryptedPrivateKey' => "{$user}-private-key", 'publicKey' => "{$user}-public-key"]]), 200, "registration of {$user}");
        $this->installation->set("{$user}.email", $email);
        $this->installation->set("{$user}.password", 'client-hash');
        $this->ok($this->login($user), 200, "login of {$user}");
        $this->installation->set("{$user}.id", $this->ok($this->get($user, '/api/accounts/profile'))->jsonString('id'));
    }

    /**
     * A password login from the user's device, which keeps the tokens on success.
     *
     * @param  array<string, string>  $fields  To add or replace
     */
    private function login(string $user, array $fields = [], ?string $as = null): Exchange
    {
        $login = $this->server->form('/identity/connect/token', [...LoginTest::loginFields($this->installation->string("{$user}.email"), $this->password($user)), ...$fields]);
        if ($login->status === 200) {
            $this->installation->set(($as ?? $user).'.token', $login->jsonString('access_token'));
            $this->installation->set(($as ?? $user).'.refresh', $login->jsonString('refresh_token'));
        }

        return $login;
    }

    private function password(string $user): string
    {
        return $this->installation->string("{$user}.password");
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function cipher(string $user, int $type, string $name, array $data): string
    {
        return $this->ok($this->post($user, '/api/ciphers', ['type' => $type, 'name' => $name, 'key' => '2.cipher-key',
            'encryptedFor' => $this->installation->string("{$user}.id"), ...$data]))->jsonString('id');
    }

    private function attachment(string $user, string $cipher, string $contents): void
    {
        $created = $this->ok($this->post($user, "/api/ciphers/{$cipher}/attachment/v2", ['key' => '2.attachment-key', 'fileName' => '2.file-name', 'fileSize' => strlen($contents)]));
        $id = $created->jsonString('attachmentId');
        $this->ok($this->server->multipart("/api/ciphers/{$cipher}/attachment/{$id}", [['data', $contents, '2.file-name']], $this->installation->auth($user)));
        $this->installation->push('attachments', [$user, $cipher, $id]);
    }

    private function fileSend(string $user, string $contents): void
    {
        $created = $this->ok($this->post($user, '/api/sends/file/v2', ['type' => 1, 'key' => '2.send-key', 'name' => '2.file-send', 'file' => ['fileName' => '2.send-file'],
            'fileLength' => strlen($contents), 'deletionDate' => self::days(30), 'disabled' => false]));
        $id = $created->jsonString('sendResponse.id');
        $this->ok($this->server->multipart("/api/sends/{$id}/file/{$created->jsonString('sendResponse.file.id')}", [['data', $contents, '2.send-file']],
            $this->installation->auth($user)));
        $this->installation->push('sends', [$created->jsonString('sendResponse.accessId'), null]);
    }

    /**
     * Invites a user by mail, who accepts with the mailed token; returns the membership id.
     *
     * @param  list<array<string, mixed>>  $collections
     */
    private function join(string $user, int $type, array $collections, bool $confirm = true): string
    {
        $org = $this->installation->string('org');
        $email = $this->installation->string("{$user}.email");
        $this->ok($this->post('owner', "/api/organizations/{$org}/users/invite", ['emails' => [$email], 'groups' => [], 'type' => $type, 'collections' => $collections]));
        $memberId = $this->memberId($user);
        $this->ok($this->post($user, "/api/organizations/{$org}/users/{$memberId}/accept", ['token' => $this->server->mailedToken($email)]));
        if ($confirm) {
            $this->ok($this->post('owner', "/api/organizations/{$org}/users/{$memberId}/confirm", ['key' => "4.{$user}-org-key"]));
        }

        return $memberId;
    }

    private function memberId(string $user): string
    {
        $members = $this->ok($this->get('owner', "/api/organizations/{$this->installation->string('org')}/users"))->json('data');
        foreach (is_array($members) ? $members : [] as $member) {
            if (is_array($member) && ($member['email'] ?? null) === $this->installation->string("{$user}.email") && is_string($member['id'] ?? null)) {
                return $member['id'];
            }
        }

        throw new RuntimeException("{$user} is no member.");
    }

    /**
     * The owner invites a user as emergency contact; returns the id.
     */
    private function trust(string $user, int $type, int $waitTimeDays): string
    {
        $email = $this->installation->string("{$user}.email");
        $this->ok($this->post('owner', '/api/emergency-access/invite', ['email' => $email, 'type' => $type, 'waitTimeDays' => $waitTimeDays]));
        $trusted = $this->ok($this->get('owner', '/api/emergency-access/trusted'))->json('data');
        foreach (is_array($trusted) ? $trusted : [] as $access) {
            if (is_array($access) && ($access['email'] ?? null) === $email && is_string($access['id'] ?? null)) {
                return $access['id'];
            }
        }

        throw new RuntimeException("No emergency access for {$user}.");
    }

    private function authenticator(string $user): void
    {
        $setup = $this->ok($this->post($user, '/api/two-factor/get-authenticator', ['masterPasswordHash' => $this->password($user)]));
        $this->installation->set("{$user}.totp", $setup->jsonString('authenticator.key'));
        $this->installation->set("{$user}.totp.step", 0);
        $this->ok($this->post($user, '/api/two-factor/authenticator', ['key' => $setup->jsonString('authenticator.key'),
            'userVerificationToken' => $setup->jsonString('userVerificationToken'), 'token' => $this->totp($user)]));
    }

    private function securityKey(string $user, SoftwareAuthenticator $key, int $id): void
    {
        $token = $this->ok($this->post($user, '/api/two-factor/get-webauthn', ['masterPasswordHash' => $this->password($user)]))->jsonString('userVerificationToken');
        $challenge = $this->ok($this->post($user, '/api/two-factor/get-webauthn-challenge', ['userVerificationToken' => $token]));
        $this->ok($this->post($user, '/api/two-factor/webauthn', ['id' => $id, 'name' => "Key {$id}", 'userVerificationToken' => $token,
            'deviceResponse' => $key->register(TwoFactorTest::options($challenge))]));
    }

    /**
     * A code of the user's authenticator for a time step the server has not
     * seen yet; it takes one step either side of its own. Waits if need be.
     */
    private function totp(string $user): string
    {
        $secret = Base32::decode($this->installation->string("{$user}.totp")) ?? '';
        $last = $this->installation->get("{$user}.totp.step");
        $step = max(is_int($last) ? $last + 1 : 0, intdiv(time(), 30));
        while ($step > intdiv(time(), 30) + 1) {
            sleep(1);
        }
        $this->installation->set("{$user}.totp.step", $step);

        return AuthenticatorController::totp($secret, $step * 30);
    }

    private function mailedCode(string $to): string
    {
        return preg_match('/\b(\d{6})\b/', $this->server->mail($to)->text, $match) === 1 ? $match[1] : throw new RuntimeException("No code in the mail to {$to}.");
    }

    /**
     * A login request from the user's first device, approved or not by its browser.
     */
    private function authRequest(string $user, bool $approve): void
    {
        $code = 'access-code-'.bin2hex(random_bytes(8));
        $request = $this->ok($this->server->json('POST', '/api/auth-requests', ['accessCode' => $code, 'deviceIdentifier' => LoginTest::DEVICE,
            'email' => $this->installation->string("{$user}.email"), 'publicKey' => 'request-public-key', 'type' => 0], ['Device-Type' => '25']));
        $id = $request->jsonString('id');
        if ($approve) {
            $this->ok($this->put("{$user}-browser", "/api/auth-requests/{$id}", ['deviceIdentifier' => self::BROWSER, 'key' => '4.request-key',
                'masterPasswordHash' => null, 'requestApproved' => true]));
            $this->installation->push('auth-requests', [$id, $code]);
        }
        $this->installation->push('auth-request-ids', [$id]);
    }

    /**
     * @param  array<string, int|string>  $kdf
     */
    private function changeKdf(string $user, array $kdf, string $password): void
    {
        $data = ['salt' => $this->installation->string("{$user}.email"), 'kdf' => $kdf];
        $this->ok($this->post($user, '/api/accounts/kdf', ['masterPasswordHash' => $this->password($user),
            'authenticationData' => [...$data, 'masterPasswordAuthenticationHash' => $password],
            'unlockData' => [...$data, 'masterKeyWrappedUserKey' => "{$user}-key-2"]]));
        $this->installation->set("{$user}.password", $password);
        $this->ok($this->login($user));
    }

    /**
     * Every page of an event list, in a stable order: events of one second
     * have no order of their own.
     */
    private function events(string $path): Exchange
    {
        $events = [];
        $query = self::RANGE;
        do {
            $page = $this->ok($this->get('owner', "{$path}?{$query}"));
            $events = [...$events, ...(array) $page->json('data')];
            $continuation = $page->json('continuationToken');
            $query = self::RANGE.'&continuationToken='.(is_string($continuation) ? rawurlencode($continuation) : '');
        } while (is_string($continuation));
        $encoded = array_map(static fn (mixed $event): string => (string) json_encode($event), $events);
        sort($encoded);

        return $page->withBody('{"data":['.implode(',', $encoded).']}');
    }

    /**
     * A date some days from now; Sends live 31 days at most.
     */
    private static function days(int $days): string
    {
        return gmdate('Y-m-d\TH:i:s.000\Z', time() + $days * 86400);
    }

    /**
     * The status and the body, with JSON decoded and tokens replaced.
     */
    private static function view(Exchange $exchange): string
    {
        $body = $exchange->isJson() ? json_decode($exchange->body) : $exchange->body;

        return (string) json_encode(['status' => $exchange->status, 'body' => self::normalized($body)],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    }

    private static function normalized(mixed $value): mixed
    {
        return match (true) {
            is_array($value) => self::rowsInOrder(array_map(self::normalized(...), $value)),
            $value instanceof stdClass => (object) array_map(self::normalized(...), get_object_vars($value)),
            is_string($value) => (string) preg_replace('/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/', '<jwt>', $value),
            default => $value,
        };
    }

    /**
     * A page of the admin panel with the rows of its tables in a stable
     * order, for the reason of rowsInOrder().
     */
    private static function tableRowsInOrder(Exchange $page): Exchange
    {
        return $page->withBody((string) preg_replace_callback('#<tbody>(.*?)</tbody>#s', static function (array $table): string {
            preg_match_all('#<tr\b.*?</tr>#s', $table[1], $rows);
            sort($rows[0]);

            return '<tbody>'.implode("\n", $rows[0]).'</tbody>';
        }, $page->body));
    }

    /**
     * Lists of rows (objects with an id or of an API object type, or ids) in
     * a stable order. Neither Vaultwarden nor we sort them, so they come in
     * the order of each query's plan, which differs on PostgreSQL; clients
     * give it no meaning. What a row holds in order (fields, password
     * history, URIs) keeps it.
     *
     * @param  array<mixed>  $list
     * @return array<mixed>
     */
    private static function rowsInOrder(array $list): array
    {
        $rows = $list !== [] && array_is_list($list) && (array_all($list, static fn (mixed $item): bool => $item instanceof stdClass
            && (is_string($item->id ?? null) || is_string($item->object ?? null)))
            || array_all($list, static fn (mixed $item): bool => is_string($item) && preg_match('/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/', $item) === 1));
        if ($rows) {
            usort($list, static fn (mixed $a, mixed $b): int => strcmp((string) json_encode($a), (string) json_encode($b)));
        }

        return $list;
    }

    private function ok(Exchange $exchange, int $status = 200, string $label = 'request'): Exchange
    {
        $this->assertSame($status, $exchange->status, "Status of the {$label}: {$exchange->body}");

        return $exchange;
    }

    /**
     * A request to the admin panel with the session of the first login.
     *
     * @param  array<string, mixed>|null  $data
     */
    private function admin(string $method, string $path, ?array $data = null): Exchange
    {
        $headers = ['Cookie' => 'VW_ADMIN='.$this->installation->string('admin'), 'Accept' => 'application/json'];

        return $data === null ? $this->server->send($method, $path, $headers) : $this->server->json($method, $path, $data, $headers);
    }

    private function get(string $user, string $path): Exchange
    {
        return $this->server->send('GET', $path, $this->installation->auth($user));
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function post(string $user, string $path, array $data = []): Exchange
    {
        return $this->server->json('POST', $path, $data, $this->installation->auth($user));
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function put(string $user, string $path, array $data = []): Exchange
    {
        return $this->server->json('PUT', $path, $data, $this->installation->auth($user));
    }
}
