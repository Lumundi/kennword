<?php

namespace App\Http;

use Illuminate\Http\Request as LaravelRequest;
use Symfony\Component\HttpFoundation\InputBag;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * The request as Rocket sees it, captured by public/index.php.
 *
 * - The path is the whole path of the URL. Symfony would take a script name in it (/index.php/admin) as the
 *   base URL and route the rest, so a web server's rules for /admin could be walked around; Rocket has no
 *   such route and answers 404. That holds however the URL spells the script name: percent-encoded
 *   (/index%2Ephp/admin, which the web server decodes before it applies its rules) or, on a file system
 *   that ignores case, in capitals.
 * - Only Rocket's method override applies: a POST whose urlencoded form starts with a `_method` field. The
 *   query string and the X-HTTP-Method-Override header change nothing.
 * - JSON bodies are not decoded when the request is captured. App\Http\Data\Body reads them within Rocket's
 *   limit when a handler asks for them, after the request guards.
 */
class Request extends LaravelRequest
{
    /**
     * The methods Rocket's Method::from_str knows.
     */
    private const array METHODS = ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT', 'PATCH'];

    public static function capture(): static
    {
        self::setAllowedHttpMethodOverride([]);

        return static::createFromBase(SymfonyRequest::createFromGlobals());
    }

    public function getMethod(): string
    {
        return $this->method ??= $this->rocketMethod();
    }

    /**
     * @param  string|null  $key
     * @param  mixed  $default
     * @return ($key is null ? InputBag<bool|float|int|string|null> : mixed)
     */
    public function json($key = null, $default = null)
    {
        $this->json ??= new InputBag;

        return parent::json($key, $default);
    }

    protected function prepareBaseUrl(): string
    {
        $baseUrl = parent::prepareBaseUrl();

        // Symfony keeps the base URL as the request spells it, percent-encoding included.
        return str_ends_with(strtolower(rawurldecode($baseUrl)), '.php') ? '' : $baseUrl;
    }

    /**
     * Rocket's preprocess(): a form POST that starts with `_method=<method>` is handled as that method.
     */
    private function rocketMethod(): string
    {
        $method = $this->getRealMethod();
        $type = strtolower((string) $this->headers->get('Content-Type'));
        if ($method !== 'POST' || ! str_starts_with($type, 'application/x-www-form-urlencoded')) {
            return $method;
        }

        $head = stream_get_contents($this->getContent(true), 64);
        if (! is_string($head) || ! str_starts_with($head, '_method=')) {
            return $method;
        }
        $override = strtoupper(explode('&', substr($head, strlen('_method=')), 2)[0]);

        return in_array($override, self::METHODS, true) ? $override : $method;
    }
}
