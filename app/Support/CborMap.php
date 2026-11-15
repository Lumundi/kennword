<?php

namespace App\Support;

/**
 * A CBOR map, whose keys may be of any type. A text key is a PHP string,
 * a byte string key a CborBytes; a repeated key keeps the last value.
 * Scalar keys are indexed, so decoding a map takes linear time; keys of
 * other types (arrays, maps, tags, NaN) are compared one by one.
 */
final class CborMap
{
    /**
     * @var list<array{mixed, mixed}>
     */
    private array $entries = [];

    /**
     * @var array<string, int> Entry by indexed key
     */
    private array $index = [];

    /**
     * @var list<int> Entries whose keys are not indexed
     */
    private array $others = [];

    public function set(mixed $key, mixed $value): void
    {
        $found = $this->find($key);
        if ($found !== null) {
            $this->entries[$found] = [$key, $value];

            return;
        }
        $this->entries[] = [$key, $value];
        $position = array_key_last($this->entries);
        $indexKey = self::indexKey($key);
        if ($indexKey === null) {
            $this->others[] = $position;
        } else {
            $this->index[$indexKey] = $position;
        }
    }

    public function has(mixed $key): bool
    {
        return $this->find($key) !== null;
    }

    public function get(mixed $key): mixed
    {
        $found = $this->find($key);

        return $found === null ? null : $this->entries[$found][1];
    }

    /**
     * @return list<array{mixed, mixed}>
     */
    public function entries(): array
    {
        return $this->entries;
    }

    private function find(mixed $key): ?int
    {
        $indexKey = self::indexKey($key);
        if ($indexKey !== null) {
            return $this->index[$indexKey] ?? null;
        }
        foreach ($this->others as $position) {
            if (self::same($this->entries[$position][0], $key)) {
                return $position;
            }
        }

        return null;
    }

    /**
     * A string that two keys share exactly when same() holds for them, or
     * null for keys that are only compared one by one.
     */
    private static function indexKey(mixed $key): ?string
    {
        return match (true) {
            is_string($key) => "s{$key}",
            $key instanceof CborBytes => "b{$key->bytes}",
            is_int($key) => "i{$key}",
            is_bool($key) => $key ? 't' : 'f',
            $key === null => 'n',
            // 0.0 === -0.0 holds and NaN === NaN does not.
            is_float($key) && ! is_nan($key) => 'd'.($key == 0.0 ? '0' : pack('E', $key)),
            default => null,
        };
    }

    private static function same(mixed $a, mixed $b): bool
    {
        return $a instanceof CborBytes && $b instanceof CborBytes ? $a->bytes === $b->bytes : $a === $b;
    }
}
