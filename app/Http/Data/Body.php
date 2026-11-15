<?php

namespace App\Http\Data;

use App\Http\HttpStatus;
use Illuminate\Http\Request;

/**
 * Rocket's body data guards: Json<T> and Form<T>.
 */
final class Body
{
    /**
     * The "json" limit of src/main.rs (20.megabytes()).
     */
    public const int JSON_LIMIT = 20_000_000;

    /**
     * Rocket's Limits::FORM for urlencoded forms, which Vaultwarden leaves as it is.
     */
    public const int FORM_LIMIT = 32 * 1024;

    /**
     * serde_json's recursion limit: 127 nested arrays or objects, which is
     * PHP's depth 128. Deeper documents are a syntax error, so a 400.
     */
    public const int JSON_DEPTH = 128;

    /**
     * Json<T>: the content type is not checked; invalid JSON is a 400.
     *
     * @throws HttpStatus
     */
    public static function json(Request $request): Fields
    {
        $decoded = json_decode(self::content($request, self::JSON_LIMIT), false, self::JSON_DEPTH, JSON_BIGINT_AS_STRING);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new HttpStatus(400, 'Invalid JSON: '.json_last_error_msg());
        }

        return Fields::of($decoded);
    }

    /**
     * Json<Vec<T>>: a list of objects; anything else is a 422.
     *
     * @return list<Fields>
     *
     * @throws HttpStatus
     */
    public static function jsonList(Request $request): array
    {
        $decoded = json_decode(self::content($request, self::JSON_LIMIT), false, self::JSON_DEPTH, JSON_BIGINT_AS_STRING);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new HttpStatus(400, 'Invalid JSON: '.json_last_error_msg());
        }
        if (! is_array($decoded) || ! array_is_list($decoded)) {
            throw new HttpStatus(422, 'Expected a JSON array.');
        }

        return array_map(Fields::of(...), $decoded);
    }

    /**
     * Form<T>: an urlencoded or multipart body, as the values of each name.
     *
     * @return array<string, list<string>> Lower-case names
     *
     * @throws HttpStatus
     */
    public static function form(Request $request): array
    {
        $type = strtolower((string) $request->headers->get('Content-Type'));
        if (! str_starts_with($type, 'application/x-www-form-urlencoded') && ! str_starts_with($type, 'multipart/form-data')) {
            throw new HttpStatus(415, 'Expected a form.');
        }

        $fields = [];
        if (str_starts_with($type, 'multipart/form-data')) {
            foreach ($request->request->all() as $name => $value) {
                if (is_string($value)) {
                    $fields[strtolower((string) $name)][] = $value;
                }
            }

            return $fields;
        }

        foreach (explode('&', self::content($request, self::FORM_LIMIT)) as $pair) {
            if ($pair === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $fields[strtolower(urldecode($name))][] = urldecode($value);
        }

        return $fields;
    }

    /**
     * A field of a lenient form under any of its names. Like an Option<T>
     * field, it is None when it is missing, given more than once, or fails
     * to parse.
     *
     * @param  array<string, list<string>>  $form
     * @param  list<string>  $names  Lower-case names and aliases
     */
    public static function optionalFormField(array $form, array $names): ?string
    {
        $values = [];
        foreach ($names as $name) {
            array_push($values, ...($form[$name] ?? []));
        }

        return count($values) === 1 ? $values[0] : null;
    }

    /**
     * The body, read up to the data guard's limit like Data::open(limit); a longer one is a 413, as Rocket
     * answers when the capped read is not complete.
     *
     * @throws HttpStatus
     */
    public static function content(Request $request, int $limit): string
    {
        $length = $request->server->get('CONTENT_LENGTH');
        if (is_numeric($length) && (int) $length > $limit) {
            throw new HttpStatus(413, 'Data limit exceeded.');
        }

        $stream = $request->getContent(true);
        $content = stream_get_contents($stream, $limit + 1);
        if (! is_string($content) || strlen($content) > $limit) {
            throw new HttpStatus(413, 'Data limit exceeded.');
        }

        return $content;
    }
}
