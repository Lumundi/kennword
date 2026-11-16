<?php

namespace App\Auth;

use App\Config\Config;
use App\Http\Unauthorized;
use App\Models\Device;
use App\Models\User;
use App\Support\Dates;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Throwable;

/**
 * The request guard of every authenticated route (auth::Headers): the user and
 * device of a valid access token whose security stamp is still current.
 * Controllers receive it by type-hinting the class.
 */
final readonly class Headers
{
    public function __construct(
        public string $host,
        public Device $device,
        public User $user,
        public string $ip,
    ) {}

    /**
     * @throws Unauthorized
     */
    public static function fromRequest(Request $request, Config $config, Jwt $jwt): self
    {
        $host = self::host($request, $config);
        $ip = ClientIp::resolve($request, $config);

        // Everything after the last "Bearer ", or the whole header without one.
        $authorization = $request->headers->get('Authorization');
        if ($authorization === null) {
            throw new Unauthorized('No access token provided');
        }
        $position = strrpos($authorization, 'Bearer ');
        $token = $position === false ? $authorization : substr($authorization, $position + strlen('Bearer '));

        try {
            $claims = LoginClaims::fromArray($jwt->decode($token, JwtIssuer::Login));
        } catch (Throwable) {
            $claims = null;
        }
        if ($claims === null) {
            throw new Unauthorized('Invalid claim');
        }

        [$device, $user] = self::account($request, $claims);

        return new self($host, $device, $user, $ip);
    }

    /**
     * The device and user of an access token, as long as its security stamp
     * is current or the route is in the stamp exception.
     *
     * @return array{Device, User}
     *
     * @throws Unauthorized
     */
    public static function account(Request $request, LoginClaims $claims): array
    {
        $device = self::find(static fn () => Device::findByUuidAndUser($claims->device, $claims->sub))
            ?? throw new Unauthorized('Invalid device id');
        $user = self::find(static fn () => User::findByUuid($claims->sub))
            ?? throw new Unauthorized('Device has no user associated');

        if ($user->security_stamp !== $claims->sstamp) {
            self::checkStampException($request, $user, $claims);
        }

        return [$device, $user];
    }

    /**
     * auth::Host: DOMAIN when it is set, else the Referer, else guessed from the forwarding headers.
     */
    public static function host(Request $request, Config $config): string
    {
        if ($config->bool('domain_set')) {
            return $config->string('domain');
        }

        $referer = $request->headers->get('Referer');
        if ($referer !== null) {
            return $referer;
        }

        $protocol = $request->headers->get('X-Forwarded-Proto') ?? (getenv('ROCKET_TLS') !== false ? 'https' : 'http');
        $host = $request->headers->get('X-Forwarded-Host') ?? $request->headers->get('Host') ?? '';

        return "{$protocol}://{$host}";
    }

    /**
     * After a password change, the routes in the stamp exception may still
     * use the previous stamp for two minutes.
     *
     * @throws Unauthorized
     */
    private static function checkStampException(Request $request, User $user, LoginClaims $claims): void
    {
        $exception = json_decode((string) $user->stamp_exception, true);
        if (! is_array($exception) || ! is_array($exception['routes'] ?? null)
            || ! is_string($exception['security_stamp'] ?? null) || ! is_int($exception['expire'] ?? null)) {
            throw new Unauthorized('Invalid security stamp');
        }

        // Route names end in the name of the Rust handler, which is what the exception lists.
        $route = $request->route()?->getName();
        if ($route === null) {
            throw new Unauthorized('Error getting current route for stamp exception');
        }
        $separator = strrpos($route, '::');
        $handler = $separator === false ? $route : substr($route, $separator + 2);

        if (Dates::now()->getTimestamp() > $exception['expire']) {
            // An expired exception is removed, so that it is not checked again.
            $user->resetStampException();
            try {
                $user->save();
            } catch (Throwable $error) {
                logger()->error("Error updating user: {$error->getMessage()}");
            }

            throw new Unauthorized('Stamp exception is expired');
        }
        if (! in_array($handler, $exception['routes'], true)) {
            throw new Unauthorized('Invalid security stamp: Current route and exception route do not match');
        }
        if ($exception['security_stamp'] !== $claims->sstamp) {
            throw new Unauthorized('Invalid security stamp for matched stamp exception');
        }
    }

    /**
     * A lookup whose database error counts as not found, like Diesel's `.ok()`.
     *
     * @template T
     *
     * @param  callable(): ?T  $lookup
     * @return T|null
     */
    private static function find(callable $lookup): mixed
    {
        try {
            return $lookup();
        } catch (QueryException) {
            return null;
        }
    }
}
