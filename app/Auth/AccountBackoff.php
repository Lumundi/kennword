<?php

namespace App\Auth;

use App\Http\ApiError;
use App\Models\User;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use LogicException;

/**
 * Kennword's backoff per account, next to the rate limits per address, which
 * guesses from many addresses get around. It counts failed checks of the
 * master password hash and of the codes of two-factor methods and protected
 * actions. After MAX_FAILURES of them within WINDOW seconds, the account
 * answers 429 until the oldest is that old; nothing locks an account for
 * good. A check counts as failed while it runs, so that parallel guesses
 * cannot pass the limit, and one that succeeds takes back its own attempt
 * only. The attempts live in the cache, like the rate limits, so all PHP
 * workers share them.
 */
final readonly class AccountBackoff
{
    public const int MAX_FAILURES = 10;

    public const int WINDOW = 15 * 60;

    public const string MESSAGE = 'Too many failed attempts. Try again later.';

    public function __construct(
        private Repository $cache,
    ) {}

    /**
     * A master password hash as proof.
     *
     * @throws ApiError With status 429 while the account is held back
     */
    public function checkPassword(User $user, string $passwordHash): bool
    {
        return $this->attempt($user->uuid, static fn (): bool => $user->checkValidPassword($passwordHash));
    }

    /**
     * A check of a secret of the account, which fails when it returns false or throws.
     *
     * @param  callable(): bool  $check
     *
     * @throws ApiError With status 429 while the account is held back
     */
    public function attempt(string $userUuid, callable $check): bool
    {
        return $this->guard("user:{$userUuid}", $check);
    }

    /**
     * A login for an address without an account counts against the address,
     * so that the 429 does not tell which addresses have one.
     *
     * @throws ApiError With status 429 while the address is held back
     */
    public function failUnknown(string $email): void
    {
        $this->guard('mail:'.hash('sha256', mb_strtolower(trim($email))), static fn (): bool => false);
    }

    /**
     * @param  callable(): bool  $check
     *
     * @throws ApiError
     */
    private function guard(string $account, callable $check): bool
    {
        $key = "vaultwarden:backoff:{$account}";
        // Not numeric, which PHP would make an integer key.
        $id = 'a'.bin2hex(random_bytes(8));
        $counted = $this->update($key, static function (array $attempts, float $now) use ($id): array {
            if (count($attempts) >= self::MAX_FAILURES) {
                return [$attempts, false];
            }
            $attempts[$id] = $now;

            return [$attempts, true];
        });
        if (! $counted) {
            throw ApiError::message(self::MESSAGE, 429);
        }

        $valid = false;
        try {
            $valid = $check();
        } finally {
            if ($valid) {
                $this->update($key, static function (array $attempts) use ($id): array {
                    unset($attempts[$id]);

                    return [$attempts, true];
                });
            }
        }

        return $valid;
    }

    /**
     * Changes the attempts within the window (their times by an id of each), under a lock.
     *
     * @param  callable(array<string, float>, float): array{array<string, float>, bool}  $change
     */
    private function update(string $key, callable $change): bool
    {
        $store = $this->cache->getStore();
        if (! $store instanceof LockProvider) {
            throw new LogicException('The cache store must support locks.');
        }

        return $store->lock("{$key}:lock", 5)->block(5, function () use ($key, $change): bool {
            $now = microtime(true);
            $stored = $this->cache->get($key);
            $attempts = [];
            foreach (is_array($stored) ? $stored : [] as $id => $time) {
                if (is_string($id) && is_float($time) && $time > $now - self::WINDOW) {
                    $attempts[$id] = $time;
                }
            }
            [$attempts, $result] = $change($attempts, $now);

            if ($attempts === []) {
                $this->cache->forget($key);
            } else {
                $this->cache->put($key, $attempts, (int) ceil(max($attempts) + self::WINDOW - $now) + 1);
            }

            return $result;
        }) === true;
    }
}
