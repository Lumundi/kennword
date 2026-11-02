<?php

namespace Tests\Unit\Release;

use App\Release\ArchiveWriter;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The release archives, unpacked with tar and unzip as on a server.
 */
class ArchiveWriterTest extends TestCase
{
    /**
     * 30 October 2026, 12:34:56 UTC.
     */
    private const int TIMESTAMP = 1793363696;

    private const string LONG_PATH = 'vendor/laravel/framework/src/Illuminate/Foundation/resources/exceptions/renderer/components/laravel-ascii-spotlight.blade.php';

    private string $folder;

    protected function setUp(): void
    {
        $this->folder = sys_get_temp_dir().'/vw-archive-'.bin2hex(random_bytes(6));
        foreach ([
            'artisan' => "#!/usr/bin/env php\n<?php\n",
            'README.md' => "# Kennword\n",
            'storage/logs/.gitignore' => "*\n!.gitignore\n",
            'data/empty' => '',
            self::LONG_PATH => str_repeat('<div>ascii</div>', 4000),
        ] as $path => $content) {
            @mkdir(dirname("{$this->folder}/{$path}"), recursive: true);
            file_put_contents("{$this->folder}/{$path}", $content);
        }
        mkdir("{$this->folder}/bootstrap/cache", recursive: true);
        chmod("{$this->folder}/artisan", 0750);
        chmod("{$this->folder}/README.md", 0600);
    }

    protected function tearDown(): void
    {
        exec('rm -rf '.escapeshellarg($this->folder));
    }

    public function test_tar_and_unzip_unpack_the_folder_with_normal_modes_and_one_time(): void
    {
        $writer = new ArchiveWriter($this->folder, 'kennword-1.0.0', self::TIMESTAMP);
        $writer->writeTarGz("{$this->folder}.tar.gz");
        $writer->writeZip("{$this->folder}.zip");

        foreach (['tar' => 'tar -xzf %s -C %s', 'zip' => 'unzip -q %s -d %s'] as $format => $command) {
            $target = "{$this->folder}-{$format}";
            mkdir($target);
            exec(sprintf($command, escapeshellarg("{$this->folder}.".($format === 'tar' ? 'tar.gz' : 'zip')), escapeshellarg($target)), result_code: $status);
            $this->assertSame(0, $status, "{$format} cannot unpack the archive.");

            $root = "{$target}/kennword-1.0.0";
            $this->assertSame(['README.md', 'artisan', 'bootstrap', 'data', 'storage', 'vendor'], array_values(array_diff((array) scandir($root), ['.', '..'])), $format);
            $this->assertDirectoryExists("{$root}/bootstrap/cache", $format);
            $this->assertSame('', file_get_contents("{$root}/data/empty"), $format);
            $this->assertSame(str_repeat('<div>ascii</div>', 4000), file_get_contents("{$root}/".self::LONG_PATH), $format);
            $this->assertSame(0755, fileperms("{$root}/artisan") & 0777, $format);
            $this->assertSame(0644, fileperms("{$root}/README.md") & 0777, $format);
            $this->assertSame(0755, fileperms("{$root}/storage/logs") & 0777, $format);
            $this->assertSame(self::TIMESTAMP, filemtime("{$root}/README.md"), $format);
            exec('rm -rf '.escapeshellarg($target));
        }
        unlink("{$this->folder}.tar.gz");
        unlink("{$this->folder}.zip");
    }

    public function test_the_same_files_give_the_same_bytes(): void
    {
        $writer = new ArchiveWriter($this->folder, 'kennword-1.0.0', self::TIMESTAMP);
        $writer->writeTarGz("{$this->folder}-1.tar.gz");
        $writer->writeZip("{$this->folder}-1.zip");

        // Other times, other modes and another owner do not show.
        touch("{$this->folder}/README.md", self::TIMESTAMP + 3600);
        chmod("{$this->folder}/README.md", 0664);
        chmod("{$this->folder}/artisan", 0700);
        $writer->writeTarGz("{$this->folder}-2.tar.gz");
        $writer->writeZip("{$this->folder}-2.zip");

        foreach (['tar.gz', 'zip'] as $extension) {
            $this->assertSame(hash_file('sha256', "{$this->folder}-1.{$extension}"), hash_file('sha256', "{$this->folder}-2.{$extension}"), $extension);
            unlink("{$this->folder}-1.{$extension}");
            unlink("{$this->folder}-2.{$extension}");
        }
    }

    public function test_the_gzip_header_names_no_time_and_no_host(): void
    {
        (new ArchiveWriter($this->folder, 'kennword-1.0.0', self::TIMESTAMP))->writeTarGz("{$this->folder}.tar.gz");

        $this->assertSame("\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03", substr((string) file_get_contents("{$this->folder}.tar.gz"), 0, 10));
        unlink("{$this->folder}.tar.gz");
    }

    public function test_entries_are_sorted_by_path_below_the_top_folder(): void
    {
        $names = array_column((new ArchiveWriter($this->folder, 'kennword-1.0.0', self::TIMESTAMP))->entries(), 'name');

        $this->assertSame('kennword-1.0.0/', $names[0]);
        $this->assertSame('kennword-1.0.0/README.md', $names[1]);
        $sorted = $names;
        sort($sorted, SORT_STRING);
        $this->assertSame($sorted, $names);
    }

    public function test_symbolic_links_are_refused(): void
    {
        symlink("{$this->folder}/README.md", "{$this->folder}/link.md");

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('link.md is a symbolic link');
        (new ArchiveWriter($this->folder, 'kennword-1.0.0', self::TIMESTAMP))->entries();
    }
}
