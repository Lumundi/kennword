<?php

namespace Tests\Feature\Http;

use App\Config\Config;
use App\Support\RateLimiter;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\Repository;
use Illuminate\Filesystem\Filesystem;
use Tests\TestCase;

/**
 * The limits keep an entry per client address; in a file cache, expired
 * entries must not stay on disk for good.
 */
class RateLimiterCacheTest extends TestCase
{
    public function test_expired_entries_of_a_file_cache_are_removed(): void
    {
        $directory = "{$this->dataFolder}/cache";
        $cache = new Repository(new FileStore(new Filesystem, $directory));
        $limiter = new RateLimiter($this->app->make(Config::class), $cache);

        $limiter->check('unauthenticated', '192.0.2.1');
        $cache->put('live', 'value', 3600);
        mkdir("{$directory}/0a/1b", 0777, true);
        file_put_contents("{$directory}/0a/1b/expired", '0000000001'.serialize(1));
        file_put_contents("{$directory}/.gitignore", "*\n!.gitignore\n");
        $before = count(glob("{$directory}/*/*/*") ?: []);

        $limiter->purgeExpired();

        $this->assertFileDoesNotExist("{$directory}/0a/1b/expired");
        $this->assertDirectoryDoesNotExist("{$directory}/0a");
        $this->assertFileExists("{$directory}/.gitignore");
        $this->assertSame('value', $cache->get('live'));
        // The address's entry lasts a minute: it stays, the expired one went.
        $this->assertCount($before - 1, glob("{$directory}/*/*/*") ?: []);
    }
}
