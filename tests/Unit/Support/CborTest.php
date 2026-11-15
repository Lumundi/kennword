<?php

namespace Tests\Unit\Support;

use App\Auth\Webauthn\Base64UrlSafe;
use App\Support\Cbor;
use App\Support\CborBytes;
use App\Support\CborMap;
use App\Support\CborTag;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The CBOR decoder with examples of RFC 8949, appendix A, and the
 * base64 forms webauthn-rs accepts.
 */
class CborTest extends TestCase
{
    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function examples(): iterable
    {
        yield '0' => ['00', 0];
        yield '23' => ['17', 23];
        yield '24' => ['1818', 24];
        yield '1000000' => ['1a000f4240', 1000000];
        yield '1000000000000' => ['1b000000e8d4a51000', 1000000000000];
        yield '-1' => ['20', -1];
        yield '-1000' => ['3903e7', -1000];
        yield 'true' => ['f5', true];
        yield 'false' => ['f4', false];
        yield 'null' => ['f6', null];
        yield 'undefined' => ['f7', null];
        yield '1.5 as half' => ['f93e00', 1.5];
        yield '-4.0 as half' => ['f9c400', -4.0];
        yield '100000.0' => ['fa47c35000', 100000.0];
        yield '1.1' => ['fb3ff199999999999a', 1.1];
        yield 'text' => ['6449455446', 'IETF'];
        yield 'unicode text' => ['62c3bc', 'ü'];
        yield 'array' => ['8301820203820405', [1, [2, 3], [4, 5]]];
        yield 'indefinite array' => ['9f018202039f0405ffff', [1, [2, 3], [4, 5]]];
        yield 'indefinite text' => ['7f657374726561646d696e67ff', 'streaming'];
    }

    #[DataProvider('examples')]
    public function test_examples(string $hex, mixed $expected): void
    {
        $this->assertSame($expected, Cbor::decode((string) hex2bin($hex)));
    }

    public function test_bytes_maps_and_tags(): void
    {
        $bytes = Cbor::decode((string) hex2bin('5f42010243030405ff'));
        $this->assertInstanceOf(CborBytes::class, $bytes);
        $this->assertSame("\x01\x02\x03\x04\x05", $bytes->bytes);

        $map = Cbor::decode((string) hex2bin('a26161016162820203'));
        $this->assertInstanceOf(CborMap::class, $map);
        $this->assertSame([1, [2, 3]], [$map->get('a'), $map->get('b')]);

        $keyed = Cbor::decode((string) hex2bin('a201022003'));
        $this->assertInstanceOf(CborMap::class, $keyed);
        $this->assertSame([2, 3], [$keyed->get(1), $keyed->get(-1)]);
        $this->assertNull($keyed->get('1'));

        $tag = Cbor::decode((string) hex2bin('c074323031332d30332d32315432303a30343a30305a'));
        $this->assertInstanceOf(CborTag::class, $tag);
        $this->assertSame([0, '2013-03-21T20:04:00Z'], [$tag->tag, $tag->value]);

        // The first item and the bytes it took, as authenticator data needs.
        $this->assertSame([1, 1], Cbor::decodeFirst("\x01\x02"));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformed(): iterable
    {
        yield 'truncated' => ['1a000f'];
        yield 'trailing data' => ['0000'];
        yield 'length beyond the data' => ['45010203'];
        yield 'unexpected break' => ['ff'];
        yield 'invalid UTF-8' => ['61ff'];
        yield 'reserved information' => ['1c'];
    }

    #[DataProvider('malformed')]
    public function test_malformed(string $hex): void
    {
        $this->expectException(InvalidArgumentException::class);
        Cbor::decode((string) hex2bin($hex));
    }

    public function test_map_keys_compare_like_identity(): void
    {
        $map = new CborMap;
        $map->set(1, 'int');
        $map->set(1.0, 'float');
        $map->set('1', 'text');
        $map->set(new CborBytes('1'), 'bytes');
        $map->set(0.0, 'zero');
        $map->set(-0.0, 'negative zero');
        $map->set(NAN, 'nan');
        $map->set(NAN, 'another nan');
        $map->set([1], 'list');
        $map->set([1], 'same list');
        $map->set(true, 'true');
        $map->set(null, 'null');
        $map->set(new CborBytes('1'), 'bytes again');

        $this->assertCount(10, $map->entries());
        $this->assertSame(['int', 'float', 'text', 'bytes again', 'negative zero', 'same list', 'true', 'null'],
            [$map->get(1), $map->get(1.0), $map->get('1'), $map->get(new CborBytes('1')), $map->get(0.0), $map->get([1]), $map->get(true), $map->get(null)]);
        $this->assertFalse($map->has(NAN));
        $this->assertFalse($map->has(false));
    }

    public function test_large_maps_decode_in_linear_time(): void
    {
        // Each key compared with every earlier one took minutes for maps like this.
        $count = 20_000;
        $data = "\xBA".pack('N', $count);
        for ($i = 0; $i < $count; $i++) {
            $data .= "\x1A".pack('N', $i)."\x00";
        }
        $start = microtime(true);
        $map = Cbor::decode($data);
        $this->assertInstanceOf(CborMap::class, $map);
        $this->assertCount($count, $map->entries());
        $this->assertLessThan(1.0, microtime(true) - $start);
    }

    public function test_base64_forms(): void
    {
        $this->assertSame('-_8', Base64UrlSafe::encode("\xfb\xff"));
        foreach (['-_8', '-_8=', '+/8=', '+/8', [251, 255]] as $form) {
            $this->assertSame("\xfb\xff", Base64UrlSafe::decode($form), (string) json_encode($form));
        }
        foreach (['-_9', '-_8==', '-/8', 'a', [256], 'x y'] as $form) {
            $this->assertNull(Base64UrlSafe::decode($form), (string) json_encode($form));
        }
    }
}
