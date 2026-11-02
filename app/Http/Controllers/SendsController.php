<?php

namespace App\Http\Controllers;

use App\Auth\Headers;
use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Auth\SendHeaders;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Data\Body;
use App\Http\Data\NumberOrString;
use App\Http\Data\Query;
use App\Http\Data\SendData;
use App\Http\Data\UploadData;
use App\Http\EmptyResponse;
use App\Http\FileResponse;
use App\Http\HttpStatus;
use App\Http\Json;
use App\Models\Attachment;
use App\Models\Device;
use App\Models\OrgPolicy;
use App\Models\Send;
use App\Notifications\Notify;
use App\Support\CheckedInt;
use App\Support\Dates;
use App\Support\EscapeDebug;
use App\Support\JsonValue;
use App\Support\UpdateType;
use App\Support\Uuid;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use stdClass;

/**
 * src/api/core/sends.rs
 */
final readonly class SendsController
{
    private const string INACCESSIBLE = 'Send does not exist or is no longer available';

    public function __construct(
        private Config $config,
        private Jwt $jwt,
        private Notify $nt,
    ) {}

    /**
     * ANON_PUSH_DEVICE: the acting device of anonymous Send accesses.
     */
    private static function anonPushDevice(): Device
    {
        $device = Device::new('00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000', '', 14);
        $device->push_uuid = '00000000-0000-0000-0000-000000000000';
        $device->refresh_token = '';

        return $device;
    }

    /**
     * GET /api/sends
     */
    public function getSends(Headers $headers): Response
    {
        $sends = Send::findByUser($headers->user->uuid)->map(static fn (Send $send): array => $send->toApi())->all();

        return Json::response(Json::sorted(['data' => array_values($sends), 'object' => 'list', 'continuationToken' => null]));
    }

    /**
     * GET /api/sends/{send_id}
     */
    public function getSend(Headers $headers, Request $request, string $sendId): Response
    {
        $send = Send::findByUuidAndUser(Uuid::parameter($request, $sendId), $headers->user->uuid)
            ?? throw ApiError::message('Send not found', logMessage: 'Invalid send uuid or does not belong to user');

        return Json::response($send->toApi());
    }

    /**
     * POST /api/sends: a text Send; files go through /api/sends/file/v2.
     */
    public function postSend(Headers $headers, Request $request): Response
    {
        $data = SendData::fromFields(Body::json($request));
        $this->enforceDisableSendPolicy($headers);
        $this->enforceDisableHideEmailPolicy($data, $headers);

        if ($data->type === Send::TYPE_FILE) {
            throw ApiError::message('File sends should use /api/sends/file/v2');
        }

        $send = $this->createSend($data, $headers->user->uuid);
        $send->save();
        $this->nt->sendSendUpdate(UpdateType::SyncSendCreate, $send, $send->updateUsersRevision(), $headers->device);

        return Json::response($send->toApi());
    }

    /**
     * POST /api/sends/file/v2: the record of a file Send, and where to upload the file.
     */
    public function postSendFileV2(Headers $headers, Request $request): Response
    {
        $data = SendData::fromFields(Body::json($request));
        $this->enforceDisableSendPolicy($headers);

        if ($data->type !== Send::TYPE_FILE) {
            throw ApiError::message('Send content is not a file');
        }
        $this->enforceDisableHideEmailPolicy($data, $headers);

        $fileLength = $data->fileLength === null ? throw ApiError::message('Invalid send length') : NumberOrString::intoI64($data->fileLength);
        if ($fileLength < 0) {
            throw ApiError::message("Send size can't be negative");
        }

        $limitKb = $this->config->optionalInt('user_send_limit');
        if ($limitKb === 0) {
            throw ApiError::message('File uploads are disabled');
        }
        if ($limitKb === null) {
            $sizeLimit = CiphersController::SIZE_525_MB;
        } else {
            $used = Send::sizeByUser($headers->user->uuid) ?? throw ApiError::message('Existing sends overflow');
            $left = CheckedInt::mul($limitKb, 1024);
            $left = ($left === null ? null : CheckedInt::sub($left, $used)) ?? throw ApiError::message('Send size overflow');
            if ($left <= 0) {
                throw ApiError::message('Send storage limit reached! Delete some sends to free up space');
            }
            $sizeLimit = min($left, CiphersController::SIZE_525_MB);
        }
        if ($fileLength > $sizeLimit) {
            throw ApiError::message('Send storage limit exceeded with this file');
        }

        $send = $this->createSend($data, $headers->user->uuid);

        $fileId = Send::generateFileId();
        [, $fileData] = JsonValue::decode($send->data);
        if (! $fileData instanceof stdClass) {
            throw ApiError::message('Invalid Send file data');
        }
        $fileData = [...(array) JsonValue::toArrays($fileData), 'id' => $fileId, 'size' => $fileLength, 'sizeName' => Attachment::displaySize($fileLength)];
        $send->data = Json::encode(Json::sorted($fileData));
        $send->save();

        return Json::response(Json::sorted([
            // FileUploadType::Direct: to this server, not to Azure.
            'fileUploadType' => 0,
            'object' => 'send-fileUpload',
            'url' => "/sends/{$send->uuid}/file/{$fileId}",
            'sendResponse' => $send->toApi(),
        ]));
    }

    /**
     * POST /api/sends/{send_id}/file/{file_id}: the file of a file Send, once.
     */
    public function postSendFileV2Data(Request $request, string $sendId, string $fileId): EmptyResponse
    {
        UploadData::requireMultipart($request);
        $headers = app(Headers::class);
        $sendId = Uuid::parameter($request, $sendId);
        $fileId = Uuid::idParameter($request, $fileId);
        $data = UploadData::fromRequest($request);

        $this->enforceDisableSendPolicy($headers);

        $send = Send::findByUuidAndUser($sendId, $headers->user->uuid)
            ?? throw ApiError::message('Send not found. Unable to save the file.', logMessage: 'Invalid send uuid or does not belong to user.');
        if ($send->atype !== Send::TYPE_FILE) {
            throw ApiError::message('Send is not a file type send.');
        }

        $sendFile = self::sendFileData($send) ?? throw ApiError::message('Unable to decode send data as json.');

        // The CLI may send the bare file name.
        $rawName = $data->rawName();
        if ($rawName === null) {
            throw ApiError::message('Send file name does not match or is not provided.');
        }
        if ($rawName !== $sendFile['fileName'] && ! ($headers->device->isCli() && str_ends_with($sendFile['fileName'], $rawName))) {
            throw ApiError::message('Send file name does not match.', logMessage: "Expected file name '".EscapeDebug::of($sendFile['fileName'])."' got '".EscapeDebug::of($rawName)."'");
        }

        if ($fileId !== $sendFile['id']) {
            throw ApiError::message('Send file does not match send data.', logMessage: "Expected id {$sendFile['id']} got {$fileId}");
        }

        $size = $data->size();
        if ($size !== $sendFile['size']) {
            throw ApiError::message('Send file size does not match.', logMessage: "Expected a file size of {$sendFile['size']} got {$size}");
        }

        // Written only if absent. Upstream's storage refuses an overwrite while
        // copying, so the error arrives as an io::Error.
        $path = Send::filePath($sendId, $fileId);
        if (file_exists($path)) {
            throw ApiError::message('Io', logMessage: 'ConditionNotMatch: the send file exists already');
        }
        $data->store($path);

        $this->nt->sendSendUpdate(UpdateType::SyncSendCreate, $send, $send->updateUsersRevision(), $headers->device);

        return new EmptyResponse;
    }

    /**
     * POST /api/sends/access: a text Send for whoever holds its access token.
     * File Sends count their access at the download.
     */
    public function postAccess(SendHeaders $sendHeaders): Response
    {
        $send = Send::findByUuid($sendHeaders->sendId) ?? throw ApiError::message(self::INACCESSIBLE, 404);
        if (! $send->isAccessible()) {
            throw ApiError::message(self::INACCESSIBLE, 404);
        }
        if ($send->atype === Send::TYPE_TEXT && ! $send->registerAccess()) {
            throw ApiError::message(self::INACCESSIBLE, 404);
        }

        $this->nt->sendSendUpdate(UpdateType::SyncSendUpdate, $send, $send->updateUsersRevision(), self::anonPushDevice());

        return Json::response($send->toApiAccess());
    }

    /**
     * POST /api/sends/access/file/{file_id}: the download URL of a file Send.
     */
    public function postAccessFile(SendHeaders $sendHeaders, Request $request, string $fileId): Response
    {
        $host = Headers::host($request, $this->config);
        $fileId = Uuid::idParameter($request, $fileId);

        $send = Send::findByUuid($sendHeaders->sendId) ?? throw ApiError::message(self::INACCESSIBLE, 404);
        if (! $send->isAccessible()) {
            throw ApiError::message(self::INACCESSIBLE, 404);
        }
        if ($send->atype !== Send::TYPE_FILE) {
            throw ApiError::message('Send is not a file type send.');
        }
        if ((self::sendFileData($send)['id'] ?? null) !== $fileId) {
            throw ApiError::message(self::INACCESSIBLE, 404);
        }
        if (! $send->registerAccess()) {
            throw ApiError::message(self::INACCESSIBLE, 404);
        }

        $this->nt->sendSendUpdate(UpdateType::SyncSendUpdate, $send, $send->updateUsersRevision(), self::anonPushDevice());

        $now = Dates::now()->getTimestamp();
        $token = $this->jwt->encode([
            'nbf' => $now,
            'exp' => $now + 120,
            'iss' => $this->jwt->issuer(JwtIssuer::Send),
            'sub' => "{$send->uuid}/{$fileId}",
        ]);

        return Json::response(Json::sorted([
            'object' => 'send-fileDownload',
            'id' => $fileId,
            'url' => "{$host}/api/sends/{$send->uuid}/{$fileId}?t={$token}",
        ]));
    }

    /**
     * GET /api/sends/{send_id}/{file_id}?t=: the file, for the holder of the
     * download token. Anything else is a 404.
     */
    public function downloadSend(Request $request, string $sendId, string $fileId): FileResponse
    {
        $sendId = Uuid::parameter($request, $sendId);
        $fileId = Uuid::idParameter($request, $fileId);
        // Without a token the request forwards to the web vault's catch-all.
        $token = Query::first($request, 't') ?? throw new HttpStatus(404, 'No token.');

        try {
            $claims = $this->jwt->decode($token, JwtIssuer::Send);
        } catch (ApiError) {
            throw new HttpStatus(404, 'Invalid token.');
        }
        if (($claims['sub'] ?? null) !== "{$sendId}/{$fileId}") {
            throw new HttpStatus(404, 'The token is for another file.');
        }

        $path = Send::filePath($sendId, $fileId);
        if (! is_file($path)) {
            throw new HttpStatus(404, 'No such file.');
        }

        return new FileResponse($path);
    }

    /**
     * PUT /api/sends/{send_id}
     */
    public function putSend(Headers $headers, Request $request, string $sendId): Response
    {
        $sendId = Uuid::parameter($request, $sendId);
        $data = SendData::fromFields(Body::json($request));
        $this->enforceDisableSendPolicy($headers);
        $this->enforceDisableHideEmailPolicy($data, $headers);

        $send = Send::findByUuidAndUser($sendId, $headers->user->uuid)
            ?? throw ApiError::message('Send not found', logMessage: 'Send send_id is invalid or does not belong to user');

        if ($data->emails !== null) {
            throw ApiError::message('Sends with email verification is not supported');
        }

        $this->updateSendFromData($send, $data, $headers);

        return Json::response($send->toApi());
    }

    /**
     * DELETE /api/sends/{send_id}: deleting stays allowed under the policies.
     */
    public function deleteSend(Headers $headers, Request $request, string $sendId): EmptyResponse
    {
        $send = Send::findByUuidAndUser(Uuid::parameter($request, $sendId), $headers->user->uuid)
            ?? throw ApiError::message('Send not found', logMessage: 'Invalid send uuid, or does not belong to user');

        $send->deleteSend();
        $this->nt->sendSendUpdate(UpdateType::SyncSendDelete, $send, $send->updateUsersRevision(), $headers->device);

        return new EmptyResponse;
    }

    /**
     * PUT /api/sends/{send_id}/remove-password
     */
    public function putRemovePassword(Headers $headers, Request $request, string $sendId): Response
    {
        $sendId = Uuid::parameter($request, $sendId);
        $this->enforceDisableSendPolicy($headers);

        $send = Send::findByUuidAndUser($sendId, $headers->user->uuid)
            ?? throw ApiError::message('Send not found', logMessage: 'Invalid send uuid, or does not belong to user');

        $send->setPassword(null);
        $send->save();
        $this->nt->sendSendUpdate(UpdateType::SyncSendUpdate, $send, $send->updateUsersRevision(), $headers->device);

        return Json::response($send->toApi());
    }

    /**
     * sends::create_send
     *
     * @throws ApiError
     */
    private function createSend(SendData $data, string $userUuid): Send
    {
        $value = match ($data->type) {
            Send::TYPE_TEXT => $data->text,
            Send::TYPE_FILE => $data->file,
            default => throw ApiError::message('Invalid Send type'),
        };
        $stored = self::storedData($value) ?? throw ApiError::message('Send data not provided');

        self::checkDeletionDate($data);
        if ($data->emails !== null) {
            throw ApiError::message('Sends with email verification is not supported');
        }

        $send = Send::new($data->type, $data->name, $stored, $data->key, $data->deletionDate);
        $send->user_uuid = $userUuid;
        $send->notes = $data->notes;
        $send->max_access_count = $data->maxAccessCount === null ? null : NumberOrString::intoI32($data->maxAccessCount);
        $send->expiration_date = $data->expirationDate;
        $send->disabled = $data->disabled;
        $send->hide_email = $data->hideEmail;
        $send->setPassword($data->password);

        return $send;
    }

    /**
     * sends::update_send_from_data. The data of a file Send cannot change.
     *
     * @throws ApiError
     */
    private function updateSendFromData(Send $send, SendData $data, Headers $headers): void
    {
        if ($send->user_uuid !== $headers->user->uuid) {
            throw ApiError::message('Send is not owned by user');
        }
        if ($send->atype !== $data->type) {
            throw ApiError::message("Sends can't change type");
        }
        self::checkDeletionDate($data);

        if ($data->type === Send::TYPE_TEXT) {
            $send->data = self::storedData($data->text) ?? throw ApiError::message('Send data not provided');
        }

        $send->name = $data->name;
        $send->akey = $data->key;
        $send->deletion_date = $data->deletionDate;
        $send->notes = $data->notes;
        $send->max_access_count = $data->maxAccessCount === null ? null : NumberOrString::intoI32($data->maxAccessCount);
        $send->expiration_date = $data->expirationDate;
        $send->hide_email = $data->hideEmail;
        $send->disabled = $data->disabled;
        // Only a given password changes it.
        if ($data->password !== null) {
            $send->setPassword($data->password);
        }

        $send->save();
        $this->nt->sendSendUpdate(UpdateType::SyncSendUpdate, $send, $send->updateUsersRevision(), $headers->device);
    }

    /**
     * Without its 'response' key, as serde_json writes it; null without data.
     */
    private static function storedData(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }
        if (is_array($value) && ! array_is_list($value)) {
            unset($value['response']);
        }

        return Json::encode(Json::sorted($value));
    }

    /**
     * @throws ApiError
     */
    private static function checkDeletionDate(SendData $data): void
    {
        if ($data->deletionDate > Dates::now()->modify('+31 days')) {
            throw ApiError::message('You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.');
        }
    }

    /**
     * SendFileData: the id, size and name of the file in the Send's data.
     *
     * @return array{id: string, size: int<0, max>, fileName: string}|null
     */
    private static function sendFileData(Send $send): ?array
    {
        [$ok, $data] = JsonValue::decode($send->data);
        if (! $ok || ! $data instanceof stdClass) {
            return null;
        }
        $id = $data->id ?? null;
        $size = $data->size ?? null;
        $fileName = $data->fileName ?? null;

        return is_string($id) && is_int($size) && $size >= 0 && is_string($fileName)
            ? ['id' => $id, 'size' => $size, 'fileName' => $fileName]
            : null;
    }

    /**
     * Neither the Disable Send policy nor SENDS_ALLOWED=false allow creating
     * or changing Sends; deleting them stays possible.
     *
     * @throws ApiError
     */
    private function enforceDisableSendPolicy(Headers $headers): void
    {
        if (! $this->config->bool('sends_allowed') || OrgPolicy::isApplicableToUser($headers->user->uuid, OrgPolicy::TYPE_DISABLE_SEND)) {
            throw ApiError::message('Due to an Enterprise Policy, you are only able to delete an existing Send.');
        }
    }

    /**
     * The Send Options policy may forbid hiding the email address.
     *
     * @throws ApiError
     */
    private function enforceDisableHideEmailPolicy(SendData $data, Headers $headers): void
    {
        if ($data->hideEmail === true && OrgPolicy::isHideEmailDisabled($headers->user->uuid)) {
            throw ApiError::message('Due to an Enterprise Policy, you are not allowed to hide your email address from recipients when creating or editing a Send.');
        }
    }
}
