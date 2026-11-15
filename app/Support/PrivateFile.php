<?php

namespace App\Support;

/**
 * Files that hold secrets (the key that signs every token, config.json, the
 * SQLite database and its backups) are created readable and writable by
 * their owner only, whatever the umask. Existing files keep their mode.
 */
final class PrivateFile
{
    public const int MODE = 0600;

    /**
     * Creates the file with the contents unless it exists. False when it
     * existed already, or could not be created or written (then it is gone).
     */
    public static function create(string $path, string $contents = ''): bool
    {
        $handle = @fopen($path, 'x');
        if ($handle === false) {
            return false;
        }
        // Before anything is written, so the contents are never readable by others.
        @chmod($path, self::MODE);
        $written = @fwrite($handle, $contents) === strlen($contents);
        fclose($handle);
        if (! $written) {
            @unlink($path);
        }

        return $written;
    }

    /**
     * Whether users other than the owner may read or write the file.
     * False where PHP cannot tell, as on Windows.
     */
    public static function isOpen(string $path): bool
    {
        $mode = @fileperms($path);

        return DIRECTORY_SEPARATOR === '/' && $mode !== false && ($mode & 0077) !== 0;
    }
}
