<?php

namespace Tests\Unit\Http;

use App\Http\FileResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * App\Http\FileResponse: files larger than memory_limit download whole, with or without PHP's output buffer.
 */
class FileResponseTest extends TestCase
{
    private const int SIZE = 48 * 1024 * 1024;

    private string $folder;

    protected function setUp(): void
    {
        parent::setUp();
        $this->folder = sys_get_temp_dir().'/file-response-'.bin2hex(random_bytes(4));
        mkdir($this->folder);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob("{$this->folder}/*") ?: []);
        rmdir($this->folder);
        parent::tearDown();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function outputBuffering(): iterable
    {
        yield 'no output buffer' => ['0'];
        yield 'buffer of php.ini-production' => ['4096'];
        yield 'unlimited buffer' => ['On'];
    }

    #[DataProvider('outputBuffering')]
    public function test_a_file_larger_than_the_memory_limit_is_sent_whole(string $outputBuffering): void
    {
        $file = "{$this->folder}/attachment";
        $handle = fopen($file, 'wb');
        $this->assertNotFalse($handle);
        fwrite($handle, 'first bytes');
        ftruncate($handle, self::SIZE - 10);
        fseek($handle, 0, SEEK_END);
        fwrite($handle, 'last bytes');
        fclose($handle);

        $script = "{$this->folder}/send.php";
        file_put_contents($script, '<?php require $argv[1]."/vendor/autoload.php"; (new '.FileResponse::class.'($argv[2]))->sendContent();');

        $process = proc_open(
            [PHP_BINARY, '-d', "output_buffering={$outputBuffering}", '-d', 'memory_limit=32M', $script, dirname(__DIR__, 3), $file],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        $this->assertIsResource($process);

        $hash = hash_init('sha256');
        $received = 0;
        while (($chunk = fread($pipes[1], 65536)) !== false && $chunk !== '') {
            $received += strlen($chunk);
            hash_update($hash, $chunk);
        }
        $errors = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $this->assertSame(0, proc_close($process), $errors);
        $this->assertSame(self::SIZE, $received);
        $this->assertSame(hash_file('sha256', $file), hash_final($hash));
    }

    public function test_the_content_length_is_the_files_size(): void
    {
        file_put_contents("{$this->folder}/small", 'twelve bytes');

        $this->assertSame('12', (new FileResponse("{$this->folder}/small"))->headers->get('Content-Length'));
    }
}
