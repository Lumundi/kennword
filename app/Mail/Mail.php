<?php

namespace App\Mail;

use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Config\Config;
use App\Http\ApiError;
use App\Models\Device;
use App\Models\DeviceType;
use App\Models\User;
use App\Support\FormUrlencoded;
use App\Support\LocalTimeZone;
use App\Support\Random;
use App\Templates\TemplateRenderer;
use DateTimeImmutable;
use DateTimeZone;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Header\Headers;
use Symfony\Component\Mime\Message;
use Symfony\Component\Mime\Part\AbstractPart;
use Symfony\Component\Mime\Part\Multipart\AlternativePart;
use Symfony\Component\Mime\Part\Multipart\RelatedPart;
use Symfony\Component\Mime\Part\TextPart;
use Throwable;

/**
 * Vaultwarden's mails (src/mail.rs): each renders its Handlebars templates,
 * a text and an HTML one whose first part is the subject, and goes out
 * through SMTP or sendmail. Failures are ApiErrors, which the callers
 * either pass on or log, as upstream does.
 */
final class Mail
{
    /**
     * The format of dates in mails: "Wednesday, October 28, 2026 at 11:42:22 AM UTC".
     */
    private const string DATETIME_FORMAT = 'l, F %s, Y \a\t h:i:s A';

    /**
     * @throws ApiError
     */
    public static function sendPasswordHint(string $address, ?string $hint): void
    {
        self::send($hint === null ? 'email/pw_hint_none' : 'email/pw_hint_some', $address, ['hint' => $hint]);
    }

    /**
     * @throws ApiError
     */
    public static function sendDeleteAccount(string $address, string $userUuid): void
    {
        self::send('email/delete_account', $address, [
            'user_id' => $userUuid,
            'email' => self::percentEncode($address),
            'token' => self::basicToken(JwtIssuer::Delete, $userUuid),
        ]);
    }

    /**
     * @throws ApiError
     */
    public static function sendVerifyEmail(string $address, string $userUuid): void
    {
        self::send('email/verify_email', $address, [
            'user_id' => $userUuid,
            'email' => self::percentEncode($address),
            'token' => self::basicToken(JwtIssuer::VerifyEmail, $userUuid),
        ]);
    }

    /**
     * @throws ApiError
     */
    public static function sendRegisterVerifyEmail(string $email, string $token): void
    {
        // The anchor comes before the query, which a URL builder would not do.
        self::send('email/register_verify_email', $email, [
            'url' => self::domain().'/#/finish-signup/?'.self::query(['email' => $email, 'token' => $token, 'fromEmail' => 'true']),
            'email' => $email,
        ]);
    }

    /**
     * @throws ApiError
     */
    public static function sendWelcome(string $address): void
    {
        self::send('email/welcome', $address, []);
    }

    /**
     * @throws ApiError
     */
    public static function sendWelcomeMustVerify(string $address, string $userUuid): void
    {
        self::send('email/welcome_must_verify', $address, [
            'user_id' => $userUuid,
            'token' => self::basicToken(JwtIssuer::VerifyEmail, $userUuid),
        ]);
    }

    /**
     * @throws ApiError
     */
    public static function send2faRemovedFromOrg(string $address, string $orgName): void
    {
        self::send('email/send_2fa_removed_from_org', $address, ['org_name' => $orgName]);
    }

    /**
     * @throws ApiError
     */
    public static function sendSingleOrgRemovedFromOrg(string $address, string $orgName): void
    {
        self::send('email/send_single_org_removed_from_org', $address, ['org_name' => $orgName]);
    }

    /**
     * The invitation to an organization, with the token that accepts it.
     *
     * @throws ApiError
     */
    public static function sendInvite(User $user, string $orgId, string $memberId, string $orgName, ?string $invitedByEmail): void
    {
        $jwt = app(Jwt::class);
        $now = time();
        // InviteJwtClaims
        $token = $jwt->encode([
            'nbf' => $now,
            'exp' => $now + 3600 * app(Config::class)->int('invitation_expiration_hours'),
            'iss' => $jwt->issuer(JwtIssuer::Invite),
            'sub' => $user->uuid,
            'email' => $user->email,
            'org_id' => $orgId,
            'member_id' => $memberId,
            'invited_by_email' => $invitedByEmail,
        ]);

        $query = ['email' => $user->email, 'organizationName' => $orgName, 'organizationId' => $orgId, 'organizationUserId' => $memberId, 'token' => $token];
        $config = app(Config::class);
        if ($config->bool('sso_enabled') && $config->bool('sso_only')) {
            $query['orgSsoIdentifier'] = $orgId;
        }
        // The web vault rejects the invitation without both.
        $query['initOrganization'] = 'false';
        $query['orgUserHasExistingUser'] = $user->private_key !== null ? 'true' : 'false';

        self::send('email/send_org_invite', $user->email, [
            'url' => self::domain().'/#/accept-organization/?'.self::query($query),
            'org_name' => $orgName,
        ]);
    }

    /**
     * @throws ApiError
     */
    public static function sendEmergencyAccessInvite(string $address, string $userUuid, string $emergencyAccessId, string $grantorName, string $grantorEmail): void
    {
        $jwt = app(Jwt::class);
        $now = time();
        // EmergencyAccessInviteJwtClaims
        $token = $jwt->encode([
            'nbf' => $now,
            'exp' => $now + 3600 * app(Config::class)->int('invitation_expiration_hours'),
            'iss' => $jwt->issuer(JwtIssuer::EmergencyAccessInvite),
            'sub' => $userUuid,
            'email' => $address,
            'emer_id' => $emergencyAccessId,
            'grantor_name' => $grantorName,
            'grantor_email' => $grantorEmail,
        ]);

        self::send('email/send_emergency_access_invite', $address, [
            'url' => self::domain().'/#/accept-emergency/?'.self::query(['id' => $emergencyAccessId, 'name' => $grantorName, 'email' => $address, 'token' => $token]),
            'grantor_name' => $grantorName,
        ]);
    }

    /**
     * @throws ApiError
     */
    public static function sendEmergencyAccessInviteAccepted(string $address, string $granteeEmail): void
    {
        self::send('email/emergency_access_invite_accepted', $address, ['grantee_email' => $granteeEmail]);
    }

    /**
     * @throws ApiError
     */
    public static function sendEmergencyAccessInviteConfirmed(string $address, string $grantorName): void
    {
        self::send('email/emergency_access_invite_confirmed', $address, ['grantor_name' => $grantorName]);
    }

    /**
     * @throws ApiError
     */
    public static function sendEmergencyAccessRecoveryApproved(string $address, string $grantorName): void
    {
        self::send('email/emergency_access_recovery_approved', $address, ['grantor_name' => $grantorName]);
    }

    /**
     * @throws ApiError
     */
    public static function sendEmergencyAccessRecoveryInitiated(string $address, string $granteeName, string $type, int $waitTimeDays): void
    {
        self::send('email/emergency_access_recovery_initiated', $address, ['grantee_name' => $granteeName, 'atype' => $type, 'wait_time_days' => $waitTimeDays]);
    }

    /**
     * @throws ApiError
     */
    public static function sendEmergencyAccessRecoveryReminder(string $address, string $granteeName, string $type, string $daysLeft): void
    {
        self::send('email/emergency_access_recovery_reminder', $address, ['grantee_name' => $granteeName, 'atype' => $type, 'days_left' => $daysLeft]);
    }

    /**
     * @throws ApiError
     */
    public static function sendEmergencyAccessRecoveryRejected(string $address, string $grantorName): void
    {
        self::send('email/emergency_access_recovery_rejected', $address, ['grantor_name' => $grantorName]);
    }

    /**
     * @throws ApiError
     */
    public static function sendEmergencyAccessRecoveryTimedOut(string $address, string $granteeName, string $type): void
    {
        self::send('email/emergency_access_recovery_timed_out', $address, ['grantee_name' => $granteeName, 'atype' => $type]);
    }

    /**
     * To who invited the new member.
     *
     * @throws ApiError
     */
    public static function sendInviteAccepted(string $newUserEmail, string $address, string $orgName): void
    {
        self::send('email/invite_accepted', $address, ['email' => $newUserEmail, 'org_name' => $orgName]);
    }

    /**
     * @throws ApiError
     */
    public static function sendInviteConfirmed(string $address, string $orgName): void
    {
        self::send('email/invite_confirmed', $address, ['org_name' => $orgName]);
    }

    /**
     * @throws ApiError
     */
    public static function sendNewDeviceLoggedIn(string $address, string $ip, DateTimeImmutable $date, Device $device): void
    {
        self::send('email/new_device_logged_in', $address, [
            'ip' => $ip,
            'device_name' => self::upcaseFirst($device->name),
            'device_type' => DeviceType::fromInt($device->atype)->displayName(),
            'datetime' => self::localDateTime($date),
        ]);
    }

    /**
     * @throws ApiError
     */
    public static function sendRecoverTwofactor(string $address, string $ip, DateTimeImmutable $date): void
    {
        self::send('email/recover_twofactor', $address, ['ip' => $ip, 'datetime' => self::localDateTime($date)]);
    }

    /**
     * @throws ApiError
     */
    public static function sendIncomplete2faLogin(string $address, string $ip, DateTimeImmutable $date, string $deviceName, string $deviceType): void
    {
        self::send('email/incomplete_2fa_login', $address, [
            'ip' => $ip,
            'device_name' => self::upcaseFirst($deviceName),
            'device_type' => $deviceType,
            'datetime' => self::localDateTime($date),
            'time_limit' => app(Config::class)->int('incomplete_2fa_time_limit'),
        ]);
    }

    /**
     * The code of email two-factor login.
     *
     * @throws ApiError
     */
    public static function sendToken(string $address, string $token): void
    {
        self::send('email/twofactor_email', $address, ['token' => $token]);
    }

    /**
     * @throws ApiError
     */
    public static function sendChangeEmail(string $address, string $token): void
    {
        self::send('email/change_email', $address, ['token' => $token]);
    }

    /**
     * @throws ApiError
     */
    public static function sendChangeEmailExisting(string $address, string $actingAddress): void
    {
        self::send('email/change_email_existing', $address, ['existing_address' => $address, 'acting_address' => $actingAddress]);
    }

    /**
     * @throws ApiError
     */
    public static function sendChangeEmailInvited(string $address, string $actingAddress): void
    {
        self::send('email/change_email_invited', $address, ['existing_address' => $address, 'acting_address' => $actingAddress]);
    }

    /**
     * @throws ApiError
     */
    public static function sendSsoChangeEmail(string $address): void
    {
        self::send('email/sso_change_email', $address, ['url' => self::domain().'/#/settings/account']);
    }

    /**
     * @throws ApiError
     */
    public static function sendTest(string $address): void
    {
        self::send('email/smtp_test', $address, []);
    }

    /**
     * @throws ApiError
     */
    public static function sendAdminAccountRecovery(string $address, string $userName, string $orgName, bool $resetPassword, bool $reset2fa, bool $fallback2faEmail): void
    {
        self::send('email/admin_account_recovery', $address, [
            'user_name' => $userName,
            'org_name' => $orgName,
            'reset_password' => $resetPassword,
            'reset_2fa' => $reset2fa,
            'fallback_2fa_email' => $fallback2faEmail,
        ]);
    }

    /**
     * The code that confirms a protected action.
     *
     * @throws ApiError
     */
    public static function sendProtectedActionToken(string $address, string $token): void
    {
        self::send('email/protected_action', $address, ['token' => $token]);
    }

    /**
     * get_text: the HTML template gives the subject, the text template the
     * plain body. Every string loses its HTML tags first.
     *
     * @param  array<string, mixed>  $data  Without url and img_src, which every mail has
     * @return array{string, string, string} Subject, HTML body and text body
     *
     * @throws ApiError
     */
    public static function render(string $template, array $data): array
    {
        $config = app(Config::class);
        $data = self::sanitize(['url' => $config->string('domain'), 'img_src' => $config->string('_smtp_img_src'), ...$data]);
        [$subject, $html] = self::split($template.'.html', $data);
        [, $text] = self::split($template, $data);

        return [$subject, $html, $text];
    }

    /**
     * @param  array<string, mixed>  $data
     *
     * @throws ApiError
     */
    private static function send(string $template, string $address, array $data): void
    {
        [$subject, $html, $text] = self::render($template, $data);
        self::sendEmail($address, $subject, $html, $text);
    }

    /**
     * get_template: the subject and the body, split at the marker line.
     *
     * @param  array<string, mixed>  $data
     * @return array{string, string}
     *
     * @throws ApiError
     */
    private static function split(string $template, array $data): array
    {
        try {
            $text = app(TemplateRenderer::class)->render($template, $data);
        } catch (Throwable $error) {
            throw ApiError::message("Template error: {$error->getMessage()}");
        }

        $parts = explode('<!---------------->', $text);
        if (count($parts) < 2) {
            throw ApiError::message("Template doesn't contain body");
        }
        if (count($parts) > 2) {
            throw ApiError::message('Template contains more than one body');
        }

        return [trim($parts[0]), trim($parts[1])];
    }

    /**
     * send_email: text and HTML as alternatives, the HTML with the embedded
     * images unless SMTP_EMBED_IMAGES is off.
     *
     * @throws ApiError
     */
    private static function sendEmail(string $address, string $subject, string $html, string $text): void
    {
        $config = app(Config::class);
        $from = $config->string('smtp_from');
        $at = strrpos($from, '@');
        if ($at === false) {
            throw ApiError::message('Invalid SMTP_FROM address');
        }

        $textPart = new TextPart($text, 'utf-8', 'plain');
        $htmlPart = new TextPart($html, 'utf-8', 'html');
        $body = $config->bool('smtp_embed_images')
            ? new AlternativePart($textPart, new RelatedPart($htmlPart, self::image('logo-gray.png'), self::image('mail-github.png')))
            : new AlternativePart($textPart, $htmlPart);

        try {
            $headers = new Headers;
            $headers->addIdHeader('Message-ID', Random::uuid().'@'.substr($from, $at + 1));
            $headers->addMailboxListHeader('To', [new Address($address)]);
            $headers->addMailboxListHeader('From', [new Address($from, $config->string('smtp_from_name'))]);
            $headers->addTextHeader('Subject', $subject);
            $envelope = new Envelope(new Address($from), [new Address($address)]);
        } catch (Throwable $error) {
            throw ApiError::message("Invalid email address: {$error->getMessage()}");
        }

        app(Transport::class)->send(new Message($headers, $body), $envelope);
    }

    private static function image(string $name): AbstractPart
    {
        return new InlineImage((string) file_get_contents(resource_path("vaultwarden/static/images/{$name}")), $name);
    }

    /**
     * sanitize_data: HTML tags are removed from every string.
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    private static function sanitize(array $data): array
    {
        array_walk_recursive($data, static function (mixed &$value): void {
            if (is_string($value)) {
                $value = (string) preg_replace('/<[^>]+>/', '', $value);
            }
        });

        return $data;
    }

    /**
     * BasicJwtClaims of mailed links, valid for the invitation lifetime.
     */
    private static function basicToken(JwtIssuer $issuer, string $subject): string
    {
        $jwt = app(Jwt::class);
        $now = time();

        return $jwt->encode([
            'nbf' => $now,
            'exp' => $now + 3600 * app(Config::class)->int('invitation_expiration_hours'),
            'iss' => $jwt->issuer($issuer),
            'sub' => $subject,
        ]);
    }

    private static function domain(): string
    {
        return app(Config::class)->string('domain');
    }

    /**
     * url's form_urlencoded serializer: letters, digits and `*-._` stay,
     * spaces become `+`, everything else is percent-encoded.
     *
     * @param  array<string, string>  $pairs
     */
    private static function query(array $pairs): string
    {
        return FormUrlencoded::encode($pairs);
    }

    /**
     * percent_encode with NON_ALPHANUMERIC: only letters and digits stay.
     */
    private static function percentEncode(string $value): string
    {
        return (string) preg_replace_callback('/[^A-Za-z0-9]/', static fn (array $match): string => '%'.strtoupper(bin2hex($match[0])), $value);
    }

    private static function upcaseFirst(string $value): string
    {
        return mb_strtoupper(mb_substr($value, 0, 1)).mb_substr($value, 1);
    }

    /**
     * util::format_naive_datetime_local with "%A, %B %_d, %Y at %r %Z": in
     * the TZ time zone with its abbreviation, else in the local one with its offset.
     */
    private static function localDateTime(DateTimeImmutable $date): string
    {
        $zone = getenv('TZ');
        try {
            $timezone = is_string($zone) && $zone !== '' ? new DateTimeZone($zone) : null;
        } catch (Throwable) {
            $timezone = null;
        }
        $local = $date->setTimezone($timezone ?? LocalTimeZone::get());

        return $local->format(sprintf(self::DATETIME_FORMAT, str_pad($local->format('j'), 2, ' ', STR_PAD_LEFT))).' '.$local->format($timezone !== null ? 'T' : 'P');
    }
}
