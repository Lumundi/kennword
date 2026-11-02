<?php

namespace Tests\Unit\Http;

use App\Http\ApiError;
use PHPUnit\Framework\TestCase;

class ApiErrorTest extends TestCase
{
    public function test_the_user_message_leaves_out_the_log_value(): void
    {
        $error = ApiError::message('Organization not found', logMessage: "Organization id's do not match");

        $this->assertSame('Organization not found', $error->userMessage());
        $this->assertSame("Organization not found. Organization id's do not match", $error->debugText());
    }

    public function test_silent_errors_answer_alike_but_keep_out_of_the_log(): void
    {
        $silent = ApiError::silent('Your password hint is: secret');

        $this->assertTrue($silent->silent);
        $this->assertTrue($silent->withStatus(404)->silent);
        $this->assertSame(ApiError::message('Your password hint is: secret')->displayText(), $silent->displayText());

        // err_silent!(message, ErrorEvent { .. }) keeps its event.
        $failed = ApiError::silent('Existing SSO user with same email', event: 1005);
        $this->assertSame([true, 1005], [$failed->silent, $failed->event]);
    }

    public function test_the_user_message_of_other_kinds(): void
    {
        // Error::empty() is named after its kind; err_json! carries its log value as the message.
        $this->assertSame(['Empty', ''], [ApiError::empty()->userMessage(), ApiError::empty()->debugText()]);
        $this->assertSame('Two factor required', ApiError::json(['error' => 'invalid_grant'], 'Two factor required')->userMessage());
        $this->assertSame('Compact', ApiError::compact('Compact')->userMessage());
    }
}
