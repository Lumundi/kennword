<?php

namespace Tests\Unit\Auth;

use App\Models\User;
use PHPUnit\Framework\TestCase;

/**
 * crypto::hash_password: PBKDF2-HMAC-SHA256, 32 bytes.
 */
class PasswordHashTest extends TestCase
{
    public function test_it_matches_the_rfc_7914_vector(): void
    {
        // RFC 7914 section 11: P="passwd", S="salt", c=1 (first 32 of the 64 bytes).
        $this->assertSame('55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc', bin2hex(User::hashPassword('passwd', 'salt', 1)));
    }

    public function test_it_gives_the_same_bytes_as_hash_pbkdf2(): void
    {
        foreach ([1, 2, 1000, 100_000] as $iterations) {
            $this->assertSame(
                hash_pbkdf2('sha256', "client hash \x00\xff", 'a salt of 16 b', $iterations, 32, true),
                User::hashPassword("client hash \x00\xff", 'a salt of 16 b', $iterations),
            );
        }
        $this->assertSame(hash_pbkdf2('sha256', 'p', 's', 1, 32, true), User::hashPassword('p', 's', 0));
    }
}
