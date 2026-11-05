<?php

namespace Tests\Unit\Http;

use App\Http\Request;
use Illuminate\Http\Request as LaravelRequest;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * App\Http\Request: the path, method and body as Rocket sees them.
 */
class RequestTest extends TestCase
{
    private const array SCRIPT = ['SCRIPT_NAME' => '/index.php', 'SCRIPT_FILENAME' => '/var/www/kennword/public/index.php'];

    public function test_a_script_name_in_the_url_stays_part_of_the_path(): void
    {
        // Symfony would route /admin, past a web server's rules for /admin; Rocket has no such route.
        $this->assertSame('/admin', LaravelRequest::create('/index.php/admin', server: self::SCRIPT)->getPathInfo());
        $this->assertSame('/index.php/admin', Request::create('/index.php/admin', server: self::SCRIPT)->getPathInfo());
        $this->assertSame('/index.php', Request::create('/index.php', server: self::SCRIPT)->getPathInfo());
        $this->assertSame('/admin', Request::create('/admin', server: self::SCRIPT)->getPathInfo());
    }

    public function test_an_encoded_script_name_in_the_url_stays_part_of_the_path(): void
    {
        // The web server decodes the path before it applies its rules: to it, these are /index.php/admin.
        foreach (['/index%2Ephp/admin', '/index%2ephp/admin', '/index.ph%70/admin', '/%69ndex.php/admin'] as $path) {
            $this->assertSame('/admin', LaravelRequest::create($path, server: self::SCRIPT)->getPathInfo(), $path);
            $this->assertSame($path, Request::create($path, server: self::SCRIPT)->getPathInfo(), $path);
        }
        $this->assertSame('/index%2Ephp', Request::create('/index%2Ephp', server: self::SCRIPT)->getPathInfo());

        $vault = ['SCRIPT_NAME' => '/vault/index.php', 'SCRIPT_FILENAME' => '/var/www/vault/index.php'];
        $this->assertSame('/vault/index%2Ephp/admin', Request::create('/vault/index%2Ephp/admin', server: $vault)->getPathInfo());
    }

    public function test_a_script_name_in_capitals_stays_part_of_the_path(): void
    {
        // On a file system that ignores case, the web server runs index.php for /INDEX.PHP as well.
        $script = ['SCRIPT_NAME' => '/INDEX.PHP', 'SCRIPT_FILENAME' => '/var/www/kennword/public/INDEX.PHP'];

        $this->assertSame('/admin', LaravelRequest::create('/INDEX.PHP/admin', server: $script)->getPathInfo());
        $this->assertSame('/INDEX.PHP/admin', Request::create('/INDEX.PHP/admin', server: $script)->getPathInfo());
    }

    public function test_only_a_leading_form_field_overrides_the_method(): void
    {
        $form = ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'];

        $this->assertSame('POST', Request::create('/api/accounts?_method=DELETE', 'POST')->getMethod());
        $this->assertSame('POST', Request::create('/api/accounts', 'POST', server: ['HTTP_X_HTTP_METHOD_OVERRIDE' => 'DELETE'])->getMethod());
        $this->assertSame('DELETE', Request::create('/api/accounts', 'POST', server: $form, content: '_method=delete&x=1')->getMethod());
        $this->assertSame('PUT', Request::create('/api/accounts', 'POST', server: $form, content: '_method=PUT')->getMethod());
        $this->assertSame('POST', Request::create('/api/accounts', 'POST', server: $form, content: 'x=1&_method=DELETE')->getMethod());
        $this->assertSame('POST', Request::create('/api/accounts', 'POST', server: $form, content: '_method=FETCH')->getMethod());
        $this->assertSame('POST', Request::create('/api/accounts', 'POST', server: ['CONTENT_TYPE' => 'text/plain'], content: '_method=DELETE')->getMethod());
        $this->assertSame('PUT', Request::create('/api/accounts', 'PUT', server: $form, content: '_method=DELETE')->getMethod());
    }

    public function test_json_bodies_are_not_decoded_when_captured(): void
    {
        $base = SymfonyRequest::create('/identity/accounts/prelogin', 'POST', server: ['CONTENT_TYPE' => 'application/json'], content: '{"email":"a@example.com"}');

        $this->assertSame(['email' => 'a@example.com'], LaravelRequest::createFromBase($base)->request->all());
        $request = Request::createFromBase($base);
        $this->assertSame([], $request->request->all());
        $this->assertSame([], $request->json()->all());
        $this->assertSame('{"email":"a@example.com"}', $request->getContent());
    }
}
