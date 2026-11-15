<?php

namespace Tests\Unit\Support;

use App\Support\PrivateFile;
use PHPUnit\Framework\TestCase;

class PrivateFileTest extends TestCase
{
    private string $folder;

    private int $umask;

    protected function setUp(): void
    {
        parent::setUp();
        $this->folder = sys_get_temp_dir().'/private-file-'.bin2hex(random_bytes(4));
        mkdir($this->folder);
        // A umask that would leave new files writable by the group and readable by everyone.
        $this->umask = umask(0002);
    }

    protected function tearDown(): void
    {
        umask($this->umask);
        array_map('unlink', glob("{$this->folder}/*") ?: []);
        rmdir($this->folder);
        parent::tearDown();
    }

    public function test_a_new_file_is_its_owners_only_whatever_the_umask(): void
    {
        $this->assertTrue(PrivateFile::create("{$this->folder}/key.pem", 'secret'));

        clearstatcache();
        $this->assertSame(0600, fileperms("{$this->folder}/key.pem") & 0777);
        $this->assertSame('secret', file_get_contents("{$this->folder}/key.pem"));
        $this->assertFalse(PrivateFile::isOpen("{$this->folder}/key.pem"));
    }

    public function test_an_existing_file_is_left_alone(): void
    {
        file_put_contents("{$this->folder}/config.json", '{}');
        chmod("{$this->folder}/config.json", 0644);

        $this->assertFalse(PrivateFile::create("{$this->folder}/config.json", '{"other":1}'));

        clearstatcache();
        $this->assertSame('{}', file_get_contents("{$this->folder}/config.json"));
        $this->assertSame(0644, fileperms("{$this->folder}/config.json") & 0777);
        $this->assertTrue(PrivateFile::isOpen("{$this->folder}/config.json"));
    }

    public function test_group_access_counts_as_open(): void
    {
        touch("{$this->folder}/db.sqlite3");
        chmod("{$this->folder}/db.sqlite3", 0640);

        $this->assertTrue(PrivateFile::isOpen("{$this->folder}/db.sqlite3"));
        $this->assertFalse(PrivateFile::isOpen("{$this->folder}/missing"));
    }
}
