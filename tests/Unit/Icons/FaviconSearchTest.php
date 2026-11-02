<?php

namespace Tests\Unit\Icons;

use App\Icons\IconService;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;
use Uri\WhatWg\Url;

/**
 * get_favicons_node: html5gum's tokenizer with the FaviconEmitter of
 * icons.rs, which reads tags, not a document tree.
 */
class FaviconSearchTest extends TestCase
{
    /**
     * @return iterable<string, array{string, list<array{int, string}>}>
     */
    public static function pages(): iterable
    {
        yield 'icon links of every kind' => [
            '<link rel="icon" href="/favicon.png"><link rel="shortcut icon" href="favicon.ico">'
            .'<link rel="apple-touch-icon-precomposed" href="https://cdn.example.net/touch.JPG">',
            [[10, 'https://example.com/favicon.png'], [30, 'https://example.com/dir/favicon.ico'], [20, 'https://cdn.example.net/touch.JPG']],
        ];
        yield 'not icons' => [
            '<link rel="mask-icon" href="/mask.svg"><link rel="ICON" href="/upper.png"><link rel="stylesheet" href="/a.css">'
            .'<link rel="icon"><link href="/no-rel.png">',
            [],
        ];
        yield 'square sizes first, 32x32 best' => [
            '<link rel=icon sizes=16x16 href=a.png><link rel=icon sizes=32x32 href=b.png><link rel=icon sizes=64x64 href=c.png>'
            .'<link rel=icon sizes=180x180 href=d.png><link rel=icon sizes=512x512 href=e.png><link rel=icon sizes=16x32 href=f.png>'
            .'<link rel=icon sizes=any href=g.svg>',
            [[4, 'https://example.com/dir/a.png'], [1, 'https://example.com/dir/b.png'], [2, 'https://example.com/dir/c.png'],
                [3, 'https://example.com/dir/d.png'], [5, 'https://example.com/dir/e.png'], [200, 'https://example.com/dir/f.png'],
                [30, 'https://example.com/dir/g.svg']],
        ];
        yield 'tag and attribute names in any case' => [
            '<LINK REL="icon" HREF="/A.PNG" SIZES="32X32">',
            [[1, 'https://example.com/A.PNG']],
        ];
        yield 'the first of duplicate attributes' => [
            '<link rel=icon href=a.png href=b.png>',
            [[10, 'https://example.com/dir/a.png']],
        ];
        yield 'nothing after the end of head' => [
            '<head><link rel=icon href=in.png></head><body><link rel=icon href=out.png>',
            [[10, 'https://example.com/dir/in.png']],
        ];
        yield 'the body too without an end of head' => [
            '<head><link rel=icon href=in.png><body><link rel=icon href=body.png>',
            [[10, 'https://example.com/dir/in.png'], [10, 'https://example.com/dir/body.png']],
        ];
        // CDATA is a bogus comment in HTML, up to the first ">".
        yield 'no links in text, scripts, comments and raw text' => [
            '<title><link rel=icon href=title.png></title><script>"<link rel=icon href=script.png>"</script>'
            .'<style><link rel=icon href=style.png></style><noscript><link rel=icon href=noscript.png></noscript>'
            .'<textarea><link rel=icon href=textarea.png></textarea><!-- <link rel=icon href=comment.png> -->'
            .'<![CDATA[ <link rel=icon href=cdata.png> ]]><link rel=icon href=after.png>',
            [[10, 'https://example.com/dir/after.png']],
        ];
        yield 'escaped script data' => [
            '<script><!--<script></script><link rel=icon href=double.png></script>--></script><link rel=icon href=after.png>',
            [[10, 'https://example.com/dir/after.png']],
        ];
        yield 'templates and SVG are just tags' => [
            '<template><link rel=icon href=t.png></template><svg><link rel=icon href=s.png></svg>',
            [[10, 'https://example.com/dir/t.png'], [10, 'https://example.com/dir/s.png']],
        ];
        yield 'character references' => [
            '<link rel=icon href="?a=1&amp;b=2&notit;&notin;&copy=3&#x41;&#65;&#0;&#128;">',
            [[30, 'https://example.com/dir/page.html?a=1&b=2&notit;%E2%88%89&copy=3AA%EF%BF%BD%E2%82%AC']],
        ];
        yield 'unquoted values' => [
            '<link rel=icon href=a&quot.png>',
            [[10, 'https://example.com/dir/a%22.png']],
        ];
        yield 'carriage returns' => [
            "<link\r\nrel=icon\r\nhref=a.png\r>",
            [[10, 'https://example.com/dir/a.png']],
        ];
        yield 'a base applies to all links' => [
            '<link rel=icon href=before.png><base href="/assets/"><link rel=icon href=after.png>',
            [[10, 'https://example.com/assets/before.png'], [10, 'https://example.com/assets/after.png']],
        ];
        yield 'each base resolves against the last' => [
            '<base href="/a/"><base href="b/"><base><base href="http://[x"><link rel=icon href=x.png>',
            [[10, 'https://example.com/a/b/x.png']],
        ];
        yield 'end tags count too' => [
            '</base href="/e/"></link rel=icon href=end.png>',
            [[10, 'https://example.com/e/end.png']],
        ];
        // The base leaves the emitter at its first href, before its second one has
        // been read: that one stays pending and goes to the next link.
        yield 'an attribute left over from an early base' => [
            '<base href="/a/" href=/b/><link rel=icon href=x.png>',
            [[30, 'https://example.com/b/']],
        ];
        // html5gum 0.9.0 (Vaultwarden 1.37.5) reads the end of an attribute name in the step
        // that started it: a flagged base still takes the attribute, or leaves the next one pending.
        yield 'a base flagged at a name that ends' => [
            '<base href=/ rel><link rel=icon href=/b.png>',
            [[10, 'https://example.com/b.png']],
        ];
        yield 'a base flagged before a further name' => [
            '<base href=/ x rel><link rel=icon href=/b.png>',
            [],
        ];
        yield 'an href that is not UTF-8' => [
            "<link rel=icon href=\"\xFF.png\">",
            [[30, 'https://example.com/dir/page.html']],
        ];
        yield 'data URLs' => [
            '<link rel=icon href="data:image/png;base64,AAAA">',
            [[30, 'data:image/png;base64,AAAA']],
        ];
    }

    /**
     * @param  list<array{int, string}>  $icons
     */
    #[DataProvider('pages')]
    public function test_icons_in_pages(string $html, array $icons): void
    {
        $url = Url::parse('https://example.com/dir/page.html');
        $this->assertNotNull($url);

        $this->assertSame($icons, IconService::faviconsInPage($html, $url));
    }
}
