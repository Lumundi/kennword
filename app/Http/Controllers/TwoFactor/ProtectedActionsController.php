<?php

namespace App\Http\Controllers\TwoFactor;

use App\Auth\AccountBackoff;
use App\Auth\Headers;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Data\Body;
use App\Http\Data\PasswordOrOtpData;
use App\Http\EmptyResponse;
use App\Mail\Mail;
use App\Models\TwoFactor;
use App\Support\Random;
use Illuminate\Http\Request;

/**
 * src/api/core/two_factor/protected_actions.rs: a mailed code instead of the
 * master password, for users who log in without one. The code is stored as
 * ProtectedActionData: {token, token_sent (UNIX seconds), attempts}.
 */
final readonly class ProtectedActionsController
{
    private const string MAIL_DISABLED = 'Email is disabled for this server. Either enable email or login using your master password instead of login via device.';

    public function __construct(
        private Config $config,
        private AccountBackoff $backoff,
    ) {}

    /**
     * POST /api/accounts/request-otp: one code at a time, at most every 30 seconds.
     */
    public function requestOtp(Headers $headers): EmptyResponse
    {
        if (! $this->config->mailEnabled()) {
            throw ApiError::message(self::MAIL_DISABLED);
        }
        $user = $headers->user;

        $previous = TwoFactor::findByUserAndType($user->uuid, TwoFactor::TYPE_PROTECTED_ACTIONS);
        if ($previous !== null) {
            $elapsed = time() - PasswordOrOtpData::protectedActionData($previous->data)['token_sent'];
            if ($elapsed < 30) {
                throw ApiError::message('Please wait '.(30 - $elapsed).' seconds before requesting another code.');
            }
            $previous->deleteTwoFactor();
        }

        $size = $this->config->int('email_token_size');
        $token = $size < 1 ? '' : Random::numeric($size);
        TwoFactor::new($user->uuid, TwoFactor::TYPE_PROTECTED_ACTIONS, PasswordOrOtpData::encodeProtectedActionData($token, time(), 0))->save();
        Mail::sendProtectedActionToken($user->email, $token);

        return new EmptyResponse;
    }

    /**
     * POST /api/accounts/verify-otp: used up by one check, for the vault export.
     */
    public function verifyOtp(Headers $headers, Request $request): EmptyResponse
    {
        $otp = Body::json($request)->string('OTP', 'otp');
        if (! $this->config->mailEnabled()) {
            throw ApiError::message(self::MAIL_DISABLED);
        }

        // Counts towards the account's backoff (Kennword).
        $this->backoff->attempt($headers->user->uuid,
            fn (): bool => PasswordOrOtpData::validateProtectedActionOtp($otp, $headers->user->uuid, true, $this->config));

        return new EmptyResponse;
    }
}
