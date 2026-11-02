<?php

namespace App\Http\Controllers\TwoFactor;

use App\Auth\ClientIp;
use App\Auth\Headers;
use App\Auth\TwoFactorTokens;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Data\Body;
use App\Http\Data\PasswordOrOtpData;
use App\Http\EmptyResponse;
use App\Http\Json;
use App\Mail\Mail;
use App\Models\AuthRequest;
use App\Models\Event;
use App\Models\TwoFactor;
use App\Models\TwoFactorIncomplete;
use App\Models\User;
use App\Support\CheckedInt;
use App\Support\Dates;
use App\Support\EscapeDebug;
use App\Support\JsonValue;
use App\Support\Random;
use App\Support\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use stdClass;

/**
 * src/api/core/two_factor/email.rs: codes by mail. The address may differ
 * from the account's; it is checked with a code before the method is on.
 * The method stores EmailTokenData: {email, last_token, token_sent, attempts}.
 */
final readonly class EmailController
{
    public function __construct(
        private Config $config,
        private RateLimiter $limiter,
    ) {}

    /**
     * POST /api/two-factor/send-email-login: a login asks for its code,
     * without a session: with the password, a login request or a pending login.
     */
    public function sendEmailLogin(Request $request): EmptyResponse
    {
        $body = Body::json($request);
        $deviceIdentifier = $body->optionalString('deviceIdentifier', 'DeviceIdentifier');
        $email = $body->optionalString('email', 'Email');
        $masterPasswordHash = $body->optionalString('masterPasswordHash', 'MasterPasswordHash');
        $authRequestId = $body->optionalString('authRequestId');
        $authRequestAccessCode = $body->optionalString('authRequestAccessCode');

        if (! $this->config->bool('_enable_email_2fa')) {
            throw ApiError::message('Email 2FA is disabled');
        }
        $ip = ClientIp::resolve($request, $this->config);
        $this->limiter->check('login', $ip);
        // ClientHeaders: an unknown browser without a valid Device-Type.
        $deviceType = CheckedInt::parseI32((string) $request->headers->get('Device-Type')) ?? 14;

        $email = $email === '' ? null : $email;
        $masterPasswordHash = $masterPasswordHash === '' ? null : $masterPasswordHash;
        $authRequestId = $authRequestId === '' ? null : $authRequestId;

        if ($email !== null) {
            $logged = EscapeDebug::of($email);
            $user = User::findByMail($email)
                ?? throw ApiError::message('Username or password is incorrect. Try again', logMessage: "IP: {$ip}. Username: {$logged}.");

            if ($masterPasswordHash !== null) {
                if (! $user->checkValidPassword($masterPasswordHash)) {
                    throw ApiError::message('Username or password is incorrect. Try again', logMessage: "IP: {$ip}. Username: {$logged}.");
                }
            } elseif ($authRequestId !== null) {
                $authRequestAccessCode ?? throw ApiError::message('no auth request access code');
                $authRequest = AuthRequest::findByUuidAndUser($authRequestId, $user->uuid)
                    ?? throw ApiError::message("AuthRequest doesn't exist", logMessage: 'Invalid auth request or does not belong to user');
                $expired = Dates::now() >= $authRequest->creation_date->modify('+5 minutes');
                if ($authRequest->approved !== true || $authRequest->authentication_date !== null || $expired
                    || $authRequest->device_type !== $deviceType || $authRequest->request_ip !== $ip || ! $authRequest->checkAccessCode($authRequestAccessCode)) {
                    throw ApiError::message("AuthRequest doesn't exist", logMessage: 'Auth request not approved, already used or expired, or invalid device, IP or code');
                }
            } elseif ($deviceIdentifier !== null) {
                // Mobile SSO logins send the address and the device, but no password.
                if (TwoFactorIncomplete::findByUserAndDevice($user->uuid, $deviceIdentifier) === null) {
                    throw ApiError::message('Username or password is incorrect. Try again', logMessage: "IP: {$ip}. Username: {$logged}.");
                }
            } else {
                throw ApiError::message('No password hash has been submitted.');
            }
        } else {
            $deviceIdentifier ?? throw ApiError::message('No device identifier has been submitted.');
            // SSO logins only send the device: its latest pending login names the user.
            $userUuid = TwoFactorIncomplete::userOfDevice($deviceIdentifier);
            $user = ($userUuid === null ? null : User::findByUuid($userUuid))
                ?? throw ApiError::message('Username or password is incorrect. Try again', logMessage: "IP: {$ip}. Device: ".EscapeDebug::of($deviceIdentifier).'.');
        }

        self::sendToken($user->uuid);

        return new EmptyResponse;
    }

    /**
     * POST /api/two-factor/get-email
     */
    public function getEmail(Headers $headers, Request $request): Response
    {
        $data = PasswordOrOtpData::fromFields(Body::json($request));
        $user = $headers->user;
        $data->validate($user, false, $this->config);

        $twoFactor = TwoFactor::findByUserAndType($user->uuid, TwoFactor::TYPE_EMAIL);
        [$enabled, $email] = $twoFactor === null ? [false, null] : [true, self::tokenData($twoFactor->data)['email']];

        return Json::response(Json::sorted([
            'email' => ['enabled' => $enabled, 'email' => $email],
            'userVerificationToken' => TwoFactorTokens::email($user->uuid, $email, $enabled),
        ]));
    }

    /**
     * POST /api/two-factor/send-email: a code to the address that is to be used.
     */
    public function sendEmail(Headers $headers, Request $request): Response
    {
        $body = Body::json($request);
        $email = $body->string('email');
        $verificationToken = $body->string('userVerificationToken');
        $user = $headers->user;

        TwoFactorTokens::validateEmail($verificationToken, $user->uuid, $email, false);
        if (! $this->config->bool('_enable_email_2fa')) {
            throw ApiError::message('Email 2FA is disabled');
        }

        TwoFactor::findByUserAndType($user->uuid, TwoFactor::TYPE_EMAIL)?->deleteTwoFactor();

        // Not on until the code comes back.
        $data = self::newTokenData($email, self::generateToken());
        TwoFactor::new($user->uuid, TwoFactor::TYPE_EMAIL_VERIFICATION_CHALLENGE, self::encodeTokenData($data))->save();
        Mail::sendToken($data['email'], (string) $data['last_token']);

        return Json::response(new stdClass);
    }

    /**
     * PUT /api/two-factor/email: the code proves the address; the method is on.
     */
    public function email(Headers $headers, Request $request): Response
    {
        $body = Body::json($request);
        $email = $body->string('email');
        $token = $body->string('token');
        $verificationToken = $body->string('userVerificationToken');
        $user = $headers->user;

        TwoFactorTokens::validateEmail($verificationToken, $user->uuid, $email, false);

        $twoFactor = TwoFactor::findByUserAndType($user->uuid, TwoFactor::TYPE_EMAIL_VERIFICATION_CHALLENGE)
            ?? throw ApiError::message('Two factor not found');
        $data = self::tokenData($twoFactor->data);
        $issued = $data['last_token'] ?? throw ApiError::message('No token available');
        if (! hash_equals($issued, $token)) {
            throw ApiError::message('Token is invalid');
        }

        $twoFactor->atype = TwoFactor::TYPE_EMAIL;
        $twoFactor->data = self::encodeTokenData([...$data, 'last_token' => null, 'attempts' => 0]);
        $twoFactor->save();
        TwoFactorController::generateRecoverCode($user);
        Event::logUser(Event::USER_UPDATED_2FA, $user->uuid, $headers->device->atype, $headers->ip);

        return Json::response(new stdClass);
    }

    /**
     * DELETE /api/two-factor/email
     */
    public function disableEmail(Headers $headers, Request $request): EmptyResponse
    {
        $verificationToken = Body::json($request)->string('userVerificationToken');
        $user = $headers->user;

        $twoFactor = TwoFactor::findByUserAndType($user->uuid, TwoFactor::TYPE_EMAIL);
        if ($twoFactor !== null) {
            TwoFactorTokens::validateEmail($verificationToken, $user->uuid, self::tokenData($twoFactor->data)['email'], true);
            $twoFactor->deleteTwoFactor();
            Event::logUser(Event::USER_DISABLED_2FA, $user->uuid, $headers->device->atype, $headers->ip);
        }

        TwoFactorController::check2faState($user, $headers->device->atype, $headers->ip);

        return new EmptyResponse;
    }

    /**
     * send_token: a new code for the login, mailed to the method's address.
     *
     * @throws ApiError
     */
    public static function sendToken(string $userUuid): void
    {
        $twoFactor = TwoFactor::findByUserAndType($userUuid, TwoFactor::TYPE_EMAIL) ?? throw ApiError::message('Two factor not found');
        $data = [...self::tokenData($twoFactor->data), 'last_token' => self::generateToken(), 'token_sent' => time()];
        $twoFactor->data = self::encodeTokenData($data);
        $twoFactor->save();

        Mail::sendToken($data['email'], $data['last_token']);
    }

    /**
     * validate_email_code_str: the code of a login. Wrong codes count; after
     * the limit the code is gone. A code is used once and only in time.
     *
     * @throws ApiError
     */
    public static function validateEmailCodeStr(string $userUuid, string $token, string $data, string $ip): void
    {
        $config = app(Config::class);
        $emailData = self::tokenData($data);
        $twoFactor = TwoFactor::findByUserAndType($userUuid, TwoFactor::TYPE_EMAIL) ?? throw ApiError::message('Two factor not found');
        $issued = $emailData['last_token'] ?? throw ApiError::message("No token available! IP: {$ip}", event: Event::USER_FAILED_LOG_IN_2FA);

        if (! hash_equals($issued, $token)) {
            $emailData['attempts'] = min(PHP_INT_MAX, $emailData['attempts'] + 1);
            if ($emailData['attempts'] >= $config->int('email_attempts_limit')) {
                $emailData = [...$emailData, 'last_token' => null, 'attempts' => 0];
            }
            $twoFactor->data = self::encodeTokenData($emailData);
            $twoFactor->save();

            throw ApiError::message("Token is invalid! IP: {$ip}", event: Event::USER_FAILED_LOG_IN_2FA);
        }

        $twoFactor->data = self::encodeTokenData([...$emailData, 'last_token' => null, 'attempts' => 0]);
        $twoFactor->save();

        if (time() > $emailData['token_sent'] + $config->int('email_expiration_time')) {
            throw ApiError::message('Token has expired', event: Event::USER_FAILED_LOG_IN_2FA);
        }
    }

    /**
     * activate_email_2fa: for a verified address, the account's own; the
     * first code is sent at the next login.
     *
     * @throws ApiError
     */
    public static function activateEmail2fa(User $user): void
    {
        if ($user->verified_at === null) {
            throw ApiError::message('Auto-enabling of email 2FA failed because the users email address has not been verified!');
        }
        TwoFactor::new($user->uuid, TwoFactor::TYPE_EMAIL, self::encodeTokenData(self::newTokenData($user->email, null)))->save();
    }

    /**
     * @throws ApiError
     */
    public static function findAndActivateEmail2fa(string $userUuid): void
    {
        self::activateEmail2fa(User::findByUuid($userUuid) ?? throw ApiError::message('User not found!'));
    }

    /**
     * obscure_email: the first two characters of the name stay, shorter names are all stars.
     */
    public static function obscureEmail(string $email): string
    {
        $at = strrpos($email, '@');
        $name = $at === false ? '' : substr($email, 0, $at);
        $domain = $at === false ? $email : substr($email, $at + 1);
        $length = mb_strlen($name);

        $obscured = $length >= 1 && $length <= 3 ? str_repeat('*', $length) : substr($name, 0, 2).str_repeat('*', max(0, $length - 2));

        return "{$obscured}@{$domain}";
    }

    /**
     * The address of the method's data, for the login prompt.
     *
     * @throws ApiError
     */
    public static function methodEmail(string $data): string
    {
        return self::tokenData($data)['email'];
    }

    /**
     * EmailTokenData::from_json
     *
     * @return array{email: string, last_token: ?string, token_sent: int, attempts: int}
     *
     * @throws ApiError
     */
    private static function tokenData(string $json): array
    {
        [$ok, $value] = JsonValue::decode($json);
        $email = $ok && $value instanceof stdClass ? ($value->email ?? null) : null;
        $lastToken = $ok && $value instanceof stdClass ? ($value->last_token ?? null) : null;
        $sent = $ok && $value instanceof stdClass ? ($value->token_sent ?? null) : null;
        $attempts = $ok && $value instanceof stdClass ? ($value->attempts ?? null) : null;
        if (! is_string($email) || ($lastToken !== null && ! is_string($lastToken)) || ! is_int($sent) || ! is_int($attempts) || $attempts < 0) {
            throw ApiError::message('Could not decode EmailTokenData from string');
        }

        return ['email' => $email, 'last_token' => $lastToken, 'token_sent' => $sent, 'attempts' => $attempts];
    }

    /**
     * @return array{email: string, last_token: ?string, token_sent: int, attempts: int}
     */
    private static function newTokenData(string $email, ?string $token): array
    {
        return ['email' => $email, 'last_token' => $token, 'token_sent' => time(), 'attempts' => 0];
    }

    /**
     * @param  array{email: string, last_token: ?string, token_sent: int, attempts: int}  $data
     */
    private static function encodeTokenData(array $data): string
    {
        return Json::encode($data);
    }

    private static function generateToken(): string
    {
        $size = app(Config::class)->int('email_token_size');

        return $size < 1 ? '' : Random::numeric($size);
    }
}
