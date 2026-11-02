<?php

namespace Tests\Feature\Console;

use App\Auth\RsaKeys;
use App\Database\VaultwardenMigrator;
use App\Models\Attachment;
use App\Models\Cipher;
use App\Models\Send;
use App\Models\TwoFactor;
use App\Models\User;
use DateTimeImmutable;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Concerns\UsesVaultwardenDatabase;
use Tests\Support\SoftwareAuthenticator;
use Tests\TestCase;

/**
 * kennword:check on installations as Vaultwarden leaves them, and with
 * what needs attention. Its output may be shared, so every test also makes
 * sure that no value of a row or a setting and no path shows up in it.
 */
class VaultwardenCheckTest extends TestCase
{
    use UsesVaultwardenDatabase;

    private const string EMAIL = 'kim.private@example.com';

    protected function vaultwardenEnvironment(): array
    {
        return ['DOMAIN' => 'https://vault.example.com', 'WEB_VAULT_ENABLED' => 'false'];
    }

    #[DataProvider('drivers')]
    public function test_an_installation_as_vaultwarden_leaves_it_is_ready(string $driver): void
    {
        $this->installation($driver);
        $user = User::new(self::EMAIL, 'Kim Private');
        $user->save();
        $cipher = Cipher::new(1, '2.secret-name');
        $cipher->user_uuid = $user->uuid;
        $cipher->data = '{"username":"2.kim"}';
        $cipher->save();
        $this->attachment($cipher, 'abcdef0123456789abcd', withFile: true);
        $send = Send::new(Send::TYPE_FILE, '2.send-name', '{"id":"0123456789abcdef","fileName":"2.file","size":4}', '2.key', new DateTimeImmutable('+1 day'));
        $send->user_uuid = $user->uuid;
        $send->save();
        mkdir("{$this->dataFolder}/sends/{$send->uuid}", recursive: true);
        file_put_contents("{$this->dataFolder}/sends/{$send->uuid}/0123456789abcdef", 'file');

        [$status, $output] = $this->check();

        $this->assertSame(0, $status, $output);
        $this->assertMatchesRegularExpression('/Booked migrations \.+ (\d+) of \1/', $output);
        $this->assertMatchesRegularExpression('/Schema \.+ as Vaultwarden 1\.37\.5 creates it/', $output);
        $this->assertMatchesRegularExpression('/Users \.+ 1\b/', $output);
        $this->assertMatchesRegularExpression('/Files \.+ all found/', $output);
        $this->assertMatchesRegularExpression('/RSA key \.+ found, 2048 bits/', $output);
        $this->assertStringContainsString('Ready to move', $output);
        $this->assertPrivate($output, ['2.secret-name', '2.send-name']);
    }

    public function test_it_counts_the_rows_it_could_not_read(): void
    {
        $connection = $this->installation('sqlite');
        $user = User::new(self::EMAIL, 'Kim Private');
        $user->save();
        $broken = Cipher::new(1, '2.broken');
        $broken->user_uuid = $user->uuid;
        $broken->data = '{"password": "top-secret-value"';
        $broken->fields = 'top-secret-field';
        $broken->save();
        $unknown = Cipher::new(1, '2.unknown');
        $unknown->user_uuid = $user->uuid;
        $unknown->data = '{}';
        $unknown->save();
        $connection->table('ciphers')->where('uuid', $unknown->uuid)->update(['atype' => 42]);
        $this->attachment($broken, 'abcdef0123456789abcd', withFile: false);
        $connection->table('users')->update(['updated_at' => 'last tuesday']);

        $bytes = static fn (string $data): array => array_map(ord(...), str_split($data));
        $key = new SoftwareAuthenticator;
        TwoFactor::new($user->uuid, TwoFactor::TYPE_U2F, (string) json_encode([['id' => 1, 'name' => 'Old key', 'reg' => ['keyHandle' => $bytes($key->credentialId),
            'pubKey' => $bytes($key->publicKey()), 'attestationCert' => null, 'deviceName' => null], 'counter' => 3, 'compromised' => false, 'migrated' => null]]))->save();
        $other = User::new('other@example.com');
        $other->save();
        $point = $key->publicKey();
        TwoFactor::new($other->uuid, TwoFactor::TYPE_WEBAUTHN, (string) json_encode([['id' => 2, 'name' => 'v3 key', 'migrated' => false, 'credential' => [
            'cred_id' => $bytes($key->credentialId), 'cred' => ['type_' => 'ES256', 'key' => ['EC_EC2' => ['curve' => 'SECP256R1',
                'x' => $bytes(substr($point, 1, 32)), 'y' => $bytes(substr($point, 33))]]], 'counter' => 0, 'verified' => false, 'registration_policy' => 'discouraged',
        ]]]))->save();
        $third = User::new('third@example.com');
        $third->save();
        TwoFactor::new($third->uuid, TwoFactor::TYPE_WEBAUTHN, '[{"name": "top-secret-key"}]')->save();

        [$status, $output] = $this->check();

        $this->assertSame(1, $status, $output);
        $this->assertMatchesRegularExpression('/Ciphers of unknown types \.+ 1\b/', $output);
        $this->assertMatchesRegularExpression('/Unreadable JSON \.+ ciphers\.data 1, ciphers\.fields 1\b/', $output);
        $this->assertMatchesRegularExpression('/Timestamps \.+ users\.updated_at 1\b/', $output);
        $this->assertMatchesRegularExpression('/Files \.+ attachments 1 missing/', $output);
        $this->assertMatchesRegularExpression('/Security keys to convert \.+ 1 U2F user, 1 old WebAuthn user/', $output);
        $this->assertMatchesRegularExpression('/Security keys \.+ 1 unreadable row/', $output);
        $this->assertStringContainsString('3 problems', $output);
        $this->assertPrivate($output, ['top-secret', 'last tuesday', 'other@example.com', '2.broken']);

        // kennword:migrate converts what it can, as Vaultwarden does at every start.
        $connection->table('twofactor')->where('user_uuid', $third->uuid)->delete();
        $this->assertSame(0, Artisan::call('kennword:migrate'));
        $this->assertDoesNotMatchRegularExpression('/Security keys to convert/', $this->check()[1]);
    }

    public function test_it_compares_the_migrations_and_the_schema(): void
    {
        $connection = $this->installation('sqlite');
        $versions = array_column($this->app->make(VaultwardenMigrator::class)->migrations('sqlite'), 'version');
        $last = (string) end($versions);

        // From an older Vaultwarden.
        $connection->table(VaultwardenMigrator::TABLE)->where('version', $last)->delete();
        [$status, $output] = $this->check();
        $this->assertSame(0, $status, $output);
        $this->assertMatchesRegularExpression('/To apply \.+ 1\b/', $output);
        $this->assertMatchesRegularExpression('/Schema \.+ compared once the migrations match/', $output);

        // From a newer one.
        $connection->table(VaultwardenMigrator::TABLE)->insert([['version' => $last], ['version' => '20991231235959']]);
        [$status, $output] = $this->check();
        $this->assertSame(1, $status, $output);
        $this->assertMatchesRegularExpression('/From a newer Vaultwarden \.+ 20991231235959/', $output);

        // Changed by hand.
        $connection->table(VaultwardenMigrator::TABLE)->where('version', '20991231235959')->delete();
        $connection->statement('ALTER TABLE users DROP COLUMN avatar_color');
        $connection->statement('CREATE TABLE my_notes (id INTEGER PRIMARY KEY)');
        [$status, $output] = $this->check();
        $this->assertSame(1, $status, $output);
        $this->assertStringContainsString('Missing: users.avatar_color.', $output);
        $this->assertStringContainsString('Not Vaultwarden\'s, left alone: my_notes.', $output);
    }

    public function test_settings_that_need_attention(): void
    {
        $this->installation('sqlite');
        unlink("{$this->dataFolder}/rsa_key.pem");
        file_put_contents("{$this->dataFolder}/config.json", (string) json_encode(['domain' => 'https://kim-private.example.com', 'signups_allowed' => false]));
        $this->changeVaultwardenEnvironment(['ROCKET_PORT' => '8000', 'SIGNUPS_ALLOWED' => 'true', 'ORG_EVENTS_ENABLED' => 'maybe']);

        [$status, $output] = $this->check();

        $this->assertSame(0, $status, $output);
        $this->assertMatchesRegularExpression('/config\.json \.+ 2 settings: DOMAIN, SIGNUPS_ALLOWED/', $output);
        $this->assertMatchesRegularExpression('/Also in the environment \.+ DOMAIN, SIGNUPS_ALLOWED \(config\.json wins\)/', $output);
        $this->assertMatchesRegularExpression('/Invalid values \.+ ORG_EVENTS_ENABLED/', $output);
        $this->assertMatchesRegularExpression('/Ignored here \.+ ROCKET_PORT/', $output);
        $this->assertMatchesRegularExpression('/RSA key \.+ missing/', $output);
        $this->assertPrivate($output, ['kim-private', 'maybe', 'vault.example.com']);
    }

    public function test_settings_vaultwarden_would_refuse(): void
    {
        $this->installation('sqlite');
        $this->changeVaultwardenEnvironment(['SMTP_HOST' => 'smtp.example.com', 'SMTP_FROM' => 'top-secret-sender']);

        [$status, $output] = $this->check();

        $this->assertSame(1, $status, $output);
        $this->assertMatchesRegularExpression('/Valid \.+ no/', $output);
        $this->assertStringContainsString('Vaultwarden would not start with these settings either: SMTP_FROM. php artisan kennword:migrate tells why', $output);
        // The rest is checked all the same.
        $this->assertMatchesRegularExpression('/Schema \.+ as Vaultwarden/', $output);
        $this->assertPrivate($output, ['top-secret-sender', 'smtp.example.com']);
    }

    public function test_without_a_database(): void
    {
        config(['database.connections.sqlite.database' => "{$this->dataFolder}/db.sqlite3", 'database.default' => 'sqlite']);
        DB::purge('sqlite');

        [$status, $output] = $this->check();
        $this->assertSame(1, $status, $output);
        $this->assertMatchesRegularExpression('/SQLite database \.+ missing/', $output);
        $this->assertFileDoesNotExist("{$this->dataFolder}/db.sqlite3");

        touch("{$this->dataFolder}/db.sqlite3");
        [$status, $output] = $this->check();
        $this->assertSame(1, $status, $output);
        $this->assertStringContainsString('The database is empty.', $output);
        $this->assertPrivate($output, []);
    }

    /**
     * A migrated database with an RSA key and the folders Vaultwarden makes;
     * SQLite as a file in the data folder, where Vaultwarden keeps it.
     */
    private function installation(string $driver): Connection
    {
        if ($driver === 'sqlite') {
            touch("{$this->dataFolder}/db.sqlite3");
            config(['database.connections.sqlite.database' => "{$this->dataFolder}/db.sqlite3"]);
            DB::purge('sqlite');
        }
        $connection = $this->useDatabase($driver);
        $this->app->make(RsaKeys::class)->privateKey();
        foreach (['attachments', 'sends', 'tmp'] as $folder) {
            mkdir("{$this->dataFolder}/{$folder}");
        }

        return $connection;
    }

    private function attachment(Cipher $cipher, string $id, bool $withFile): void
    {
        Attachment::new($id, $cipher->uuid, '2.file-name', 4, '2.key')->save();
        if ($withFile) {
            mkdir("{$this->dataFolder}/attachments/{$cipher->uuid}", recursive: true);
            file_put_contents("{$this->dataFolder}/attachments/{$cipher->uuid}/{$id}", 'data');
        }
    }

    /**
     * @return array{int, string} The exit status and what the command printed
     */
    private function check(): array
    {
        $this->withoutMockingConsoleOutput();
        $status = Artisan::call('kennword:check', ['--no-ansi' => true]);

        return [$status, Artisan::output()];
    }

    /**
     * Nothing of the rows or settings in the output, and no path.
     *
     * @param  list<string>  $values
     */
    private function assertPrivate(string $output, array $values): void
    {
        foreach ([...$values, self::EMAIL, 'Kim Private', $this->dataFolder, base_path()] as $value) {
            $this->assertStringNotContainsString($value, $output);
        }
    }
}
