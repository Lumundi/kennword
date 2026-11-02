<?php

use App\Config\Config;
use App\Http\Controllers\AccountsController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\CiphersController;
use App\Http\Controllers\CoreController;
use App\Http\Controllers\EmergencyAccessController;
use App\Http\Controllers\EventsController;
use App\Http\Controllers\FoldersController;
use App\Http\Controllers\IconsController;
use App\Http\Controllers\IdentityController;
use App\Http\Controllers\NotificationsController;
use App\Http\Controllers\OrganizationsController;
use App\Http\Controllers\PublicController;
use App\Http\Controllers\SendsController;
use App\Http\Controllers\TwoFactor\AuthenticatorController;
use App\Http\Controllers\TwoFactor\DuoController;
use App\Http\Controllers\TwoFactor\EmailController;
use App\Http\Controllers\TwoFactor\ProtectedActionsController;
use App\Http\Controllers\TwoFactor\TwoFactorController;
use App\Http\Controllers\TwoFactor\WebauthnController;
use App\Http\Controllers\TwoFactor\YubikeyController;
use App\Http\Controllers\WebController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Vaultwarden's routes
|--------------------------------------------------------------------------
|
| Grouped by the mount points of src/main.rs, below DOMAIN's path. Each
| route is named after its Rust handler, as listed in PARITY.md.
|
*/

// api::web_routes()
Route::get('/alive', [WebController::class, 'alive'])->name('web::alive');
// Registered after the GET route, which would otherwise answer HEAD too.
Route::match(['HEAD'], '/alive', [WebController::class, 'aliveHead'])->name('web::alive_head');
Route::get('/attachments/{cipherId}/{fileId}', [WebController::class, 'attachments'])->name('web::attachments');
Route::get('/vw_static/{filename}', [WebController::class, 'staticFiles'])->name('web::static_files');
if (WebController::webVaultEnabled(app(Config::class))) {
    Route::get('/', [WebController::class, 'webIndex'])->name('web::web_index');
    Route::match(['HEAD'], '/', [WebController::class, 'webIndexHead'])->name('web::web_index_head');
    Route::get('/index.html', [WebController::class, 'webIndexDirect'])->name('web::web_index_direct');
    Route::get('/app-id.json', [WebController::class, 'appId'])->name('web::app_id');
    Route::get('/.well-known/apple-app-site-association', [WebController::class, 'appleAppSiteAssociation'])->name('web::apple_app_site_association');
    Route::get('/css/vaultwarden.css', [WebController::class, 'vaultwardenCss'])->name('web::vaultwarden_css');
    // Rocket ranks it below every other route; a fallback route is matched last.
    Route::fallback([WebController::class, 'webFiles'])->name('web::web_files');
}

// api::core_routes()
Route::prefix('/api')->group(function (): void {
    Route::get('/alive', [CoreController::class, 'alive'])->name('core::alive');
    Route::get('/now', [CoreController::class, 'now'])->name('core::now');
    Route::get('/version', [CoreController::class, 'version'])->name('core::version');
    Route::get('/config', [CoreController::class, 'config'])->name('core::config');
    Route::get('/hibp/breach', [CoreController::class, 'hibpBreach'])->name('core::hibp_breach');
    Route::get('/webauthn', [CoreController::class, 'getApiWebauthn'])->name('core::get_api_webauthn');
    Route::get('/settings/domains', [CoreController::class, 'getSettingsDomains'])->name('core::get_settings_domains');
    Route::post('/settings/domains', [CoreController::class, 'postSettingsDomains'])->name('core::post_settings_domains');
    Route::put('/settings/domains', [CoreController::class, 'postSettingsDomains'])->name('core::put_settings_domains');

    // core::accounts
    Route::get('/accounts/profile', [AccountsController::class, 'profile'])->name('core::accounts::profile');
    Route::put('/accounts/profile', [AccountsController::class, 'putProfile'])->name('core::accounts::put_profile');
    Route::post('/accounts/profile', [AccountsController::class, 'postProfile'])->name('core::accounts::post_profile');
    Route::put('/accounts/avatar', [AccountsController::class, 'putAvatar'])->name('core::accounts::put_avatar');
    Route::get('/users/{userId}/public-key', [AccountsController::class, 'getPublicKeys'])->name('core::accounts::get_public_keys');
    Route::get('/accounts/keys', [AccountsController::class, 'getKeys'])->name('core::accounts::get_keys');
    Route::post('/accounts/keys', [AccountsController::class, 'postKeys'])->name('core::accounts::post_keys');
    Route::get('/accounts/revision-date', [AccountsController::class, 'revisionDate'])->name('core::accounts::revision_date');
    Route::post('/accounts/set-password', [AccountsController::class, 'postSetPassword'])->name('core::accounts::post_set_password');
    Route::post('/accounts/password', [AccountsController::class, 'postPassword'])->name('core::accounts::post_password');
    Route::post('/accounts/kdf', [AccountsController::class, 'postKdf'])->name('core::accounts::post_kdf');
    Route::post('/accounts/key-management/rotate-user-account-keys', [AccountsController::class, 'postRotatekey'])->name('core::accounts::post_rotatekey');
    Route::post('/accounts/key-management/user-key-id', [AccountsController::class, 'postUserKey'])->name('core::accounts::post_user_key');
    Route::post('/accounts/security-stamp', [AccountsController::class, 'postSstamp'])->name('core::accounts::post_sstamp');
    Route::post('/accounts/email-token', [AccountsController::class, 'postEmailToken'])->name('core::accounts::post_email_token');
    Route::post('/accounts/email', [AccountsController::class, 'postEmail'])->name('core::accounts::post_email');
    Route::post('/accounts/verify-email', [AccountsController::class, 'postVerifyEmail'])->name('core::accounts::post_verify_email');
    Route::post('/accounts/verify-email-token', [AccountsController::class, 'postVerifyEmailToken'])->name('core::accounts::post_verify_email_token');
    Route::post('/accounts/delete-recover', [AccountsController::class, 'postDeleteRecover'])->name('core::accounts::post_delete_recover');
    Route::post('/accounts/delete-recover-token', [AccountsController::class, 'postDeleteRecoverToken'])->name('core::accounts::post_delete_recover_token');
    Route::post('/accounts/delete', [AccountsController::class, 'deleteAccount'])->name('core::accounts::post_delete_account');
    Route::delete('/accounts', [AccountsController::class, 'deleteAccount'])->name('core::accounts::delete_account');
    Route::post('/accounts/password-hint', [AccountsController::class, 'passwordHint'])->name('core::accounts::password_hint');
    Route::post('/accounts/verify-password', [AccountsController::class, 'verifyPassword'])->name('core::accounts::verify_password');
    Route::post('/accounts/api-key', [AccountsController::class, 'postApiKey'])->name('core::accounts::post_api_key');
    Route::post('/accounts/rotate-api-key', [AccountsController::class, 'rotateApiKey'])->name('core::accounts::rotate_api_key');
    Route::get('/devices/knowndevice', [AccountsController::class, 'getKnownDevice'])->name('core::accounts::get_known_device');
    Route::get('/devices', [AccountsController::class, 'getAllDevices'])->name('core::accounts::get_all_devices');
    Route::get('/devices/identifier/{deviceId}', [AccountsController::class, 'getDevice'])->name('core::accounts::get_device');
    Route::post('/devices/identifier/{deviceId}/token', [AccountsController::class, 'putDeviceToken'])->name('core::accounts::post_device_token');
    Route::put('/devices/identifier/{deviceId}/token', [AccountsController::class, 'putDeviceToken'])->name('core::accounts::put_device_token');
    Route::put('/devices/identifier/{deviceId}/clear-token', [AccountsController::class, 'putClearDeviceToken'])->name('core::accounts::put_clear_device_token');
    Route::post('/devices/identifier/{deviceId}/clear-token', [AccountsController::class, 'putClearDeviceToken'])->name('core::accounts::post_clear_device_token');
    Route::get('/tasks', [AccountsController::class, 'getTasks'])->name('core::accounts::get_tasks');
    Route::post('/auth-requests', [AccountsController::class, 'postAuthRequest'])->name('core::accounts::post_auth_request');
    Route::get('/auth-requests/pending', [AccountsController::class, 'getAuthRequestsPending'])->name('core::accounts::get_auth_requests_pending');
    Route::get('/auth-requests/{authRequestId}', [AccountsController::class, 'getAuthRequest'])->name('core::accounts::get_auth_request');
    Route::put('/auth-requests/{authRequestId}', [AccountsController::class, 'putAuthRequest'])->name('core::accounts::put_auth_request');
    Route::get('/auth-requests/{authRequestId}/response', [AccountsController::class, 'getAuthRequestResponse'])->name('core::accounts::get_auth_request_response');
    Route::get('/auth-requests', [AccountsController::class, 'getAuthRequestsPending'])->name('core::accounts::get_auth_requests');

    // core::ciphers
    Route::get('/sync', [CiphersController::class, 'sync'])->name('core::ciphers::sync');
    // Rocket ranks static segments above dynamic ones; Laravel takes the first match, so these come first.
    Route::delete('/ciphers', [CiphersController::class, 'deleteCiphers'])->name('core::ciphers::delete_cipher_selected');
    Route::post('/ciphers/delete', [CiphersController::class, 'deleteCiphers'])->name('core::ciphers::delete_cipher_selected_post');
    Route::put('/ciphers/delete', [CiphersController::class, 'softDeleteCiphers'])->name('core::ciphers::delete_cipher_selected_put');
    Route::delete('/ciphers/admin', [CiphersController::class, 'deleteCiphers'])->name('core::ciphers::delete_cipher_selected_admin');
    Route::post('/ciphers/delete-admin', [CiphersController::class, 'deleteCiphers'])->name('core::ciphers::delete_cipher_selected_post_admin');
    Route::put('/ciphers/delete-admin', [CiphersController::class, 'softDeleteCiphers'])->name('core::ciphers::delete_cipher_selected_put_admin');
    Route::put('/ciphers/restore', [CiphersController::class, 'restoreCiphers'])->name('core::ciphers::restore_cipher_selected');
    Route::put('/ciphers/restore-admin', [CiphersController::class, 'restoreCiphers'])->name('core::ciphers::restore_cipher_selected_admin');
    Route::post('/ciphers/move', [CiphersController::class, 'moveCiphers'])->name('core::ciphers::move_cipher_selected');
    Route::put('/ciphers/move', [CiphersController::class, 'moveCiphers'])->name('core::ciphers::move_cipher_selected_put');
    Route::post('/ciphers/purge', [CiphersController::class, 'purgeVault'])->name('core::ciphers::purge_personal_vault');
    Route::put('/ciphers/share', [CiphersController::class, 'putCipherShareSelected'])->name('core::ciphers::put_cipher_share_selected');
    Route::get('/ciphers/organization-details', [OrganizationsController::class, 'getOrgDetails'])->name('core::organizations::get_org_details');
    Route::post('/ciphers/import-organization', [OrganizationsController::class, 'postOrgImport'])->name('core::organizations::post_org_import');
    Route::post('/ciphers/bulk-collections', [OrganizationsController::class, 'postBulkCollections'])->name('core::organizations::post_bulk_collections');
    Route::post('/ciphers/create', [CiphersController::class, 'postCiphersCreate'])->name('core::ciphers::post_ciphers_create');
    Route::post('/ciphers/admin', [CiphersController::class, 'postCiphersCreate'])->name('core::ciphers::post_ciphers_admin');
    Route::post('/ciphers/import', [CiphersController::class, 'postCiphersImport'])->name('core::ciphers::post_ciphers_import');
    Route::put('/ciphers/archive', [CiphersController::class, 'archiveCiphers'])->name('core::ciphers::archive_cipher_selected');
    Route::put('/ciphers/unarchive', [CiphersController::class, 'unarchiveCiphers'])->name('core::ciphers::unarchive_cipher_selected');

    Route::get('/ciphers', [CiphersController::class, 'getCiphers'])->name('core::ciphers::get_ciphers');
    Route::get('/ciphers/{cipherId}', [CiphersController::class, 'getCipher'])->name('core::ciphers::get_cipher');
    Route::get('/ciphers/{cipherId}/admin', [CiphersController::class, 'getCipher'])->name('core::ciphers::get_cipher_admin');
    Route::get('/ciphers/{cipherId}/details', [CiphersController::class, 'getCipher'])->name('core::ciphers::get_cipher_details');
    Route::post('/ciphers', [CiphersController::class, 'postCiphers'])->name('core::ciphers::post_ciphers');
    Route::put('/ciphers/{cipherId}', [CiphersController::class, 'putCipher'])->name('core::ciphers::put_cipher');
    Route::post('/ciphers/{cipherId}', [CiphersController::class, 'putCipher'])->name('core::ciphers::post_cipher');
    Route::put('/ciphers/{cipherId}/admin', [CiphersController::class, 'putCipherAdmin'])->name('core::ciphers::put_cipher_admin');
    Route::post('/ciphers/{cipherId}/admin', [CiphersController::class, 'putCipherAdmin'])->name('core::ciphers::post_cipher_admin');
    Route::put('/ciphers/{cipherId}/partial', [CiphersController::class, 'putCipherPartial'])->name('core::ciphers::put_cipher_partial');
    Route::post('/ciphers/{cipherId}/partial', [CiphersController::class, 'putCipherPartial'])->name('core::ciphers::post_cipher_partial');
    Route::put('/ciphers/{cipherId}/share', [CiphersController::class, 'putCipherShare'])->name('core::ciphers::put_cipher_share');
    Route::post('/ciphers/{cipherId}/share', [CiphersController::class, 'putCipherShare'])->name('core::ciphers::post_cipher_share');
    Route::put('/ciphers/{cipherId}/collections', [CiphersController::class, 'putCollectionsUpdate'])->name('core::ciphers::put_collections_update');
    Route::post('/ciphers/{cipherId}/collections', [CiphersController::class, 'putCollectionsUpdate'])->name('core::ciphers::post_collections_update');
    Route::put('/ciphers/{cipherId}/collections_v2', [CiphersController::class, 'putCollections2Update'])->name('core::ciphers::put_collections2_update');
    Route::post('/ciphers/{cipherId}/collections_v2', [CiphersController::class, 'putCollections2Update'])->name('core::ciphers::post_collections2_update');
    Route::put('/ciphers/{cipherId}/collections-admin', [CiphersController::class, 'putCollectionsAdmin'])->name('core::ciphers::put_collections_admin');
    Route::post('/ciphers/{cipherId}/collections-admin', [CiphersController::class, 'putCollectionsAdmin'])->name('core::ciphers::post_collections_admin');
    Route::get('/ciphers/{cipherId}/attachment/{attachmentId}', [CiphersController::class, 'getAttachment'])->name('core::ciphers::get_attachment');
    // Before the data upload, whose attachment id would take "v2" too.
    Route::post('/ciphers/{cipherId}/attachment/v2', [CiphersController::class, 'postAttachmentV2'])->name('core::ciphers::post_attachment_v2');
    Route::post('/ciphers/{cipherId}/attachment/{attachmentId}', [CiphersController::class, 'postAttachmentV2Data'])->name('core::ciphers::post_attachment_v2_data');
    Route::post('/ciphers/{cipherId}/attachment', [CiphersController::class, 'postAttachment'])->name('core::ciphers::post_attachment');
    Route::post('/ciphers/{cipherId}/attachment-admin', [CiphersController::class, 'postAttachment'])->name('core::ciphers::post_attachment_admin');
    Route::post('/ciphers/{cipherId}/attachment/{attachmentId}/share', [CiphersController::class, 'postAttachmentShare'])->name('core::ciphers::post_attachment_share');
    Route::post('/ciphers/{cipherId}/attachment/{attachmentId}/delete-admin', [CiphersController::class, 'deleteAttachment'])->name('core::ciphers::delete_attachment_post_admin');
    Route::post('/ciphers/{cipherId}/attachment/{attachmentId}/delete', [CiphersController::class, 'deleteAttachment'])->name('core::ciphers::delete_attachment_post');
    Route::delete('/ciphers/{cipherId}/attachment/{attachmentId}', [CiphersController::class, 'deleteAttachment'])->name('core::ciphers::delete_attachment');
    Route::delete('/ciphers/{cipherId}/attachment/{attachmentId}/admin', [CiphersController::class, 'deleteAttachment'])->name('core::ciphers::delete_attachment_admin');
    Route::post('/ciphers/{cipherId}/delete', [CiphersController::class, 'deleteCipher'])->name('core::ciphers::delete_cipher_post');
    Route::post('/ciphers/{cipherId}/delete-admin', [CiphersController::class, 'deleteCipher'])->name('core::ciphers::delete_cipher_post_admin');
    Route::put('/ciphers/{cipherId}/delete', [CiphersController::class, 'softDeleteCipher'])->name('core::ciphers::delete_cipher_put');
    Route::put('/ciphers/{cipherId}/delete-admin', [CiphersController::class, 'softDeleteCipher'])->name('core::ciphers::delete_cipher_put_admin');
    Route::delete('/ciphers/{cipherId}', [CiphersController::class, 'deleteCipher'])->name('core::ciphers::delete_cipher');
    Route::delete('/ciphers/{cipherId}/admin', [CiphersController::class, 'deleteCipher'])->name('core::ciphers::delete_cipher_admin');
    Route::put('/ciphers/{cipherId}/restore', [CiphersController::class, 'restoreCipher'])->name('core::ciphers::restore_cipher_put');
    Route::put('/ciphers/{cipherId}/restore-admin', [CiphersController::class, 'restoreCipher'])->name('core::ciphers::restore_cipher_put_admin');
    Route::put('/ciphers/{cipherId}/archive', [CiphersController::class, 'archiveCipher'])->name('core::ciphers::archive_cipher_put');
    Route::put('/ciphers/{cipherId}/unarchive', [CiphersController::class, 'unarchiveCipher'])->name('core::ciphers::unarchive_cipher_put');

    // core::emergency_access; the static segments before the emergency access id, which would take them too.
    Route::get('/emergency-access/trusted', [EmergencyAccessController::class, 'getContacts'])->name('core::emergency_access::get_contacts');
    Route::get('/emergency-access/granted', [EmergencyAccessController::class, 'getGrantees'])->name('core::emergency_access::get_grantees');
    Route::post('/emergency-access/invite', [EmergencyAccessController::class, 'sendInvite'])->name('core::emergency_access::send_invite');
    Route::get('/emergency-access/{emerId}', [EmergencyAccessController::class, 'getEmergencyAccess'])->name('core::emergency_access::get_emergency_access');
    Route::put('/emergency-access/{emerId}', [EmergencyAccessController::class, 'putEmergencyAccess'])->name('core::emergency_access::put_emergency_access');
    Route::post('/emergency-access/{emerId}', [EmergencyAccessController::class, 'postEmergencyAccess'])->name('core::emergency_access::post_emergency_access');
    Route::delete('/emergency-access/{emerId}', [EmergencyAccessController::class, 'deleteEmergencyAccess'])->name('core::emergency_access::delete_emergency_access');
    Route::post('/emergency-access/{emerId}/delete', [EmergencyAccessController::class, 'postDeleteEmergencyAccess'])->name('core::emergency_access::post_delete_emergency_access');
    Route::post('/emergency-access/{emerId}/reinvite', [EmergencyAccessController::class, 'resendInvite'])->name('core::emergency_access::resend_invite');
    Route::post('/emergency-access/{emerId}/accept', [EmergencyAccessController::class, 'acceptInvite'])->name('core::emergency_access::accept_invite');
    Route::post('/emergency-access/{emerId}/confirm', [EmergencyAccessController::class, 'confirmEmergencyAccess'])->name('core::emergency_access::confirm_emergency_access');
    Route::post('/emergency-access/{emerId}/initiate', [EmergencyAccessController::class, 'initiateEmergencyAccess'])->name('core::emergency_access::initiate_emergency_access');
    Route::post('/emergency-access/{emerId}/approve', [EmergencyAccessController::class, 'approveEmergencyAccess'])->name('core::emergency_access::approve_emergency_access');
    Route::post('/emergency-access/{emerId}/reject', [EmergencyAccessController::class, 'rejectEmergencyAccess'])->name('core::emergency_access::reject_emergency_access');
    Route::post('/emergency-access/{emerId}/takeover', [EmergencyAccessController::class, 'takeoverEmergencyAccess'])->name('core::emergency_access::takeover_emergency_access');
    Route::post('/emergency-access/{emerId}/password', [EmergencyAccessController::class, 'passwordEmergencyAccess'])->name('core::emergency_access::password_emergency_access');
    Route::post('/emergency-access/{emerId}/view', [EmergencyAccessController::class, 'viewEmergencyAccess'])->name('core::emergency_access::view_emergency_access');
    Route::get('/emergency-access/{emerId}/policies', [EmergencyAccessController::class, 'policiesEmergencyAccess'])->name('core::emergency_access::policies_emergency_access');

    // core::sends
    Route::get('/sends', [SendsController::class, 'getSends'])->name('core::sends::get_sends');
    Route::post('/sends', [SendsController::class, 'postSend'])->name('core::sends::post_send');
    Route::post('/sends/file/v2', [SendsController::class, 'postSendFileV2'])->name('core::sends::post_send_file_v2');
    Route::post('/sends/access', [SendsController::class, 'postAccess'])->name('core::sends::post_access');
    // Before the file upload, whose send id would take "access" too.
    Route::post('/sends/access/file/{fileId}', [SendsController::class, 'postAccessFile'])->name('core::sends::post_access_file');
    Route::post('/sends/{sendId}/file/{fileId}', [SendsController::class, 'postSendFileV2Data'])->name('core::sends::post_send_file_v2_data');
    Route::get('/sends/{sendId}', [SendsController::class, 'getSend'])->name('core::sends::get_send');
    Route::get('/sends/{sendId}/{fileId}', [SendsController::class, 'downloadSend'])->name('core::sends::download_send');
    Route::put('/sends/{sendId}', [SendsController::class, 'putSend'])->name('core::sends::put_send');
    Route::delete('/sends/{sendId}', [SendsController::class, 'deleteSend'])->name('core::sends::delete_send');
    Route::put('/sends/{sendId}/remove-password', [SendsController::class, 'putRemovePassword'])->name('core::sends::put_remove_password');

    // core::organizations
    Route::get('/collections', [OrganizationsController::class, 'getUserCollections'])->name('core::organizations::get_user_collections');
    Route::post('/organizations', [OrganizationsController::class, 'createOrganization'])->name('core::organizations::create_organization');
    Route::get('/organizations/{orgId}', [OrganizationsController::class, 'getOrganization'])->name('core::organizations::get_organization');
    Route::put('/organizations/{orgId}', [OrganizationsController::class, 'putOrganization'])->name('core::organizations::put_organization');
    Route::delete('/organizations/{orgId}', [OrganizationsController::class, 'deleteOrganization'])->name('core::organizations::delete_organization');
    Route::post('/organizations/{orgId}/leave', [OrganizationsController::class, 'leaveOrganization'])->name('core::organizations::leave_organization');
    Route::post('/organizations/{orgId}/keys', [OrganizationsController::class, 'postOrgKeys'])->name('core::organizations::post_org_keys');
    Route::get('/organizations/{orgId}/keys', [OrganizationsController::class, 'getOrganizationPublicKey'])->name('core::organizations::get_organization_keys');
    Route::get('/organizations/{orgId}/public-key', [OrganizationsController::class, 'getOrganizationPublicKey'])->name('core::organizations::get_organization_public_key');

    Route::get('/organizations/{orgId}/collections', [OrganizationsController::class, 'getOrgCollections'])->name('core::organizations::get_org_collections');
    Route::get('/organizations/{orgId}/collections/details', [OrganizationsController::class, 'getOrgCollectionsDetails'])->name('core::organizations::get_org_collections_details');
    Route::post('/organizations/{orgId}/collections', [OrganizationsController::class, 'postOrganizationCollections'])->name('core::organizations::post_organization_collections');
    Route::delete('/organizations/{orgId}/collections', [OrganizationsController::class, 'bulkDeleteOrganizationCollections'])->name('core::organizations::bulk_delete_organization_collections');
    Route::post('/organizations/{orgId}/collections/bulk-access', [OrganizationsController::class, 'postBulkAccessCollections'])->name('core::organizations::post_bulk_access_collections');
    Route::put('/organizations/{orgId}/collections/{colId}', [OrganizationsController::class, 'putOrganizationCollectionUpdate'])->name('core::organizations::put_organization_collection_update');
    Route::delete('/organizations/{orgId}/collections/{colId}', [OrganizationsController::class, 'deleteOrganizationCollection'])->name('core::organizations::delete_organization_collection');
    Route::get('/organizations/{orgId}/collections/{colId}/details', [OrganizationsController::class, 'getOrgCollectionDetail'])->name('core::organizations::get_org_collection_detail');
    Route::get('/organizations/{orgId}/collections/{colId}/users', [OrganizationsController::class, 'getCollectionUsers'])->name('core::organizations::get_collection_users');

    Route::get('/organizations/{orgId}/export', [OrganizationsController::class, 'getOrgExport'])->name('core::organizations::get_org_export');
    Route::post('/organizations/{orgId}/api-key', [OrganizationsController::class, 'postApiKey'])->name('core::organizations::post_api_key');
    Route::post('/organizations/{orgId}/rotate-api-key', [OrganizationsController::class, 'rotateApiKey'])->name('core::organizations::rotate_api_key');
    Route::get('/plans', [OrganizationsController::class, 'getPlans'])->name('core::organizations::get_plans');
    Route::get('/organizations/{orgId}/billing/vnext/warnings', [OrganizationsController::class, 'getBillingWarnings'])->name('core::organizations::get_billing_warnings');
    Route::get('/organizations/{orgId}/billing/vnext/self-host/metadata', [OrganizationsController::class, 'getSelfHostBillingMetadata'])
        ->name('core::organizations::get_self_host_billing_metadata');
    Route::post('/organizations/domain/sso/verified', [OrganizationsController::class, 'getOrgDomainSsoVerified'])->name('core::organizations::get_org_domain_sso_verified');
    Route::get('/organizations/{identifier}/auto-enroll-status', [OrganizationsController::class, 'getAutoEnrollStatus'])->name('core::organizations::get_auto_enroll_status');
    Route::get('/organizations/{orgId}/policies', [OrganizationsController::class, 'listPolicies'])->name('core::organizations::list_policies');
    Route::get('/organizations/{orgId}/policies/token', [OrganizationsController::class, 'listPoliciesToken'])->name('core::organizations::list_policies_token');
    Route::get('/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password', [OrganizationsController::class, 'getDummyMasterPasswordPolicy'])->name('core::organizations::get_dummy_master_password_policy');
    Route::get('/organizations/{orgId}/policies/master-password', [OrganizationsController::class, 'getMasterPasswordPolicy'])->name('core::organizations::get_master_password_policy');
    Route::get('/organizations/{orgId}/policies/{polType}', [OrganizationsController::class, 'getPolicy'])->name('core::organizations::get_policy');
    Route::put('/organizations/{orgId}/policies/{polType}', [OrganizationsController::class, 'putPolicy'])->name('core::organizations::put_policy');

    Route::get('/organizations/{orgId}/groups', [OrganizationsController::class, 'getGroups'])->name('core::organizations::get_groups');
    Route::get('/organizations/{orgId}/groups/details', [OrganizationsController::class, 'getGroupsDetails'])->name('core::organizations::get_groups_details');
    Route::post('/organizations/{orgId}/groups', [OrganizationsController::class, 'postGroups'])->name('core::organizations::post_groups');
    Route::delete('/organizations/{orgId}/groups', [OrganizationsController::class, 'bulkDeleteGroups'])->name('core::organizations::bulk_delete_groups');
    Route::get('/organizations/{orgId}/groups/{groupId}', [OrganizationsController::class, 'getGroup'])->name('core::organizations::get_group');
    Route::put('/organizations/{orgId}/groups/{groupId}', [OrganizationsController::class, 'putGroup'])->name('core::organizations::put_group');
    Route::delete('/organizations/{orgId}/groups/{groupId}', [OrganizationsController::class, 'deleteGroup'])->name('core::organizations::delete_group');
    Route::get('/organizations/{orgId}/groups/{groupId}/details', [OrganizationsController::class, 'getGroupDetails'])->name('core::organizations::get_group_details');
    Route::get('/organizations/{orgId}/groups/{groupId}/users', [OrganizationsController::class, 'getGroupMembers'])->name('core::organizations::get_group_members');

    // The static member routes before those with a member id, which would take their names too.
    Route::get('/organizations/{orgId}/users', [OrganizationsController::class, 'getMembers'])->name('core::organizations::get_members');
    Route::get('/organizations/{orgId}/users/mini-details', [OrganizationsController::class, 'getOrgUserMiniDetails'])->name('core::organizations::get_org_user_mini_details');
    Route::post('/organizations/{orgId}/users/invite', [OrganizationsController::class, 'sendInvite'])->name('core::organizations::send_invite');
    Route::post('/organizations/{orgId}/users/reinvite', [OrganizationsController::class, 'bulkReinviteMembers'])->name('core::organizations::bulk_reinvite_members');
    Route::post('/organizations/{orgId}/users/confirm', [OrganizationsController::class, 'bulkConfirmInvite'])->name('core::organizations::bulk_confirm_invite');
    Route::post('/organizations/{orgId}/users/public-keys', [OrganizationsController::class, 'bulkPublicKeys'])->name('core::organizations::bulk_public_keys');
    Route::delete('/organizations/{orgId}/users', [OrganizationsController::class, 'bulkDeleteMember'])->name('core::organizations::bulk_delete_member');
    Route::put('/organizations/{orgId}/users/revoke', [OrganizationsController::class, 'bulkRevokeMembers'])->name('core::organizations::bulk_revoke_members');
    Route::put('/organizations/{orgId}/users/restore', [OrganizationsController::class, 'bulkRestoreMembers'])->name('core::organizations::bulk_restore_members');
    Route::get('/organizations/{orgId}/users/{memberId}', [OrganizationsController::class, 'getUser'])->name('core::organizations::get_user');
    Route::put('/organizations/{orgId}/users/{memberId}', [OrganizationsController::class, 'editMember'])->name('core::organizations::edit_member');
    Route::delete('/organizations/{orgId}/users/{memberId}', [OrganizationsController::class, 'deleteMember'])->name('core::organizations::delete_member');
    Route::post('/organizations/{orgId}/users/{memberId}/reinvite', [OrganizationsController::class, 'reinviteMember'])->name('core::organizations::reinvite_member');
    Route::post('/organizations/{orgId}/users/{memberId}/accept', [OrganizationsController::class, 'acceptInvite'])->name('core::organizations::accept_invite');
    Route::post('/organizations/{orgId}/users/{memberId}/confirm', [OrganizationsController::class, 'confirmInvite'])->name('core::organizations::confirm_invite');
    Route::put('/organizations/{orgId}/users/{memberId}/revoke', [OrganizationsController::class, 'revokeMember'])->name('core::organizations::revoke_member');
    Route::put('/organizations/{orgId}/users/{memberId}/restore', [OrganizationsController::class, 'restoreMember'])->name('core::organizations::restore_member');
    Route::put('/organizations/{orgId}/users/{memberId}/restore/vnext', [OrganizationsController::class, 'restoreMember'])->name('core::organizations::restore_member_vnext');
    Route::put('/organizations/{orgId}/users/{memberId}/recover-account', [OrganizationsController::class, 'putRecoverAccount'])->name('core::organizations::put_recover_account');
    Route::get('/organizations/{orgId}/users/{memberId}/reset-password-details', [OrganizationsController::class, 'getResetPasswordDetails'])->name('core::organizations::get_reset_password_details');
    Route::put('/organizations/{orgId}/users/{userId}/reset-password-enrollment', [OrganizationsController::class, 'putResetPasswordEnrollment'])->name('core::organizations::put_reset_password_enrollment');

    // core::folders
    Route::get('/folders', [FoldersController::class, 'getFolders'])->name('core::folders::get_folders');
    Route::get('/folders/{folderId}', [FoldersController::class, 'getFolder'])->name('core::folders::get_folder');
    Route::post('/folders', [FoldersController::class, 'postFolders'])->name('core::folders::post_folders');
    Route::post('/folders/{folderId}', [FoldersController::class, 'postFolder'])->name('core::folders::post_folder');
    Route::put('/folders/{folderId}', [FoldersController::class, 'putFolder'])->name('core::folders::put_folder');
    Route::post('/folders/{folderId}/delete', [FoldersController::class, 'deleteFolderPost'])->name('core::folders::delete_folder_post');
    Route::delete('/folders/{folderId}', [FoldersController::class, 'deleteFolder'])->name('core::folders::delete_folder');

    // core::events
    Route::get('/organizations/{orgId}/events', [EventsController::class, 'getOrgEvents'])->name('core::events::get_org_events');
    Route::get('/ciphers/{cipherId}/events', [EventsController::class, 'getCipherEvents'])->name('core::events::get_cipher_events');
    Route::get('/organizations/{orgId}/users/{memberId}/events', [EventsController::class, 'getUserEvents'])->name('core::events::get_user_events');

    // core::two_factor
    Route::get('/two-factor', [TwoFactorController::class, 'getTwofactor'])->name('core::two_factor::get_twofactor');
    Route::post('/two-factor/get-recover', [TwoFactorController::class, 'getRecover'])->name('core::two_factor::get_recover');
    Route::get('/two-factor/get-device-verification-settings', [TwoFactorController::class, 'getDeviceVerificationSettings'])
        ->name('core::two_factor::get_device_verification_settings');
    Route::post('/two-factor/get-authenticator', [AuthenticatorController::class, 'generateAuthenticator'])->name('core::two_factor::authenticator::generate_authenticator');
    Route::post('/two-factor/authenticator', [AuthenticatorController::class, 'activateAuthenticator'])->name('core::two_factor::authenticator::activate_authenticator');
    Route::put('/two-factor/authenticator', [AuthenticatorController::class, 'activateAuthenticator'])->name('core::two_factor::authenticator::activate_authenticator_put');
    Route::delete('/two-factor/authenticator', [AuthenticatorController::class, 'disableAuthenticator'])->name('core::two_factor::authenticator::disable_authenticator');
    Route::post('/two-factor/get-duo', [DuoController::class, 'getDuo'])->name('core::two_factor::duo::get_duo');
    Route::post('/two-factor/duo', [DuoController::class, 'activateDuo'])->name('core::two_factor::duo::activate_duo');
    Route::put('/two-factor/duo', [DuoController::class, 'activateDuo'])->name('core::two_factor::duo::activate_duo_put');
    Route::delete('/two-factor/duo', [DuoController::class, 'disableDuo'])->name('core::two_factor::duo::disable_duo');
    Route::post('/two-factor/send-email-login', [EmailController::class, 'sendEmailLogin'])->name('core::two_factor::email::send_email_login');
    Route::post('/two-factor/get-email', [EmailController::class, 'getEmail'])->name('core::two_factor::email::get_email');
    Route::post('/two-factor/send-email', [EmailController::class, 'sendEmail'])->name('core::two_factor::email::send_email');
    Route::put('/two-factor/email', [EmailController::class, 'email'])->name('core::two_factor::email::email');
    Route::delete('/two-factor/email', [EmailController::class, 'disableEmail'])->name('core::two_factor::email::disable_email');
    Route::post('/two-factor/get-webauthn', [WebauthnController::class, 'getWebauthn'])->name('core::two_factor::webauthn::get_webauthn');
    Route::post('/two-factor/get-webauthn-challenge', [WebauthnController::class, 'generateWebauthnChallenge'])
        ->name('core::two_factor::webauthn::generate_webauthn_challenge');
    Route::post('/two-factor/webauthn', [WebauthnController::class, 'activateWebauthn'])->name('core::two_factor::webauthn::activate_webauthn');
    Route::put('/two-factor/webauthn', [WebauthnController::class, 'activateWebauthn'])->name('core::two_factor::webauthn::activate_webauthn_put');
    Route::delete('/two-factor/webauthn', [WebauthnController::class, 'deleteWebauthn'])->name('core::two_factor::webauthn::delete_webauthn');
    Route::delete('/two-factor/webauthn/all', [WebauthnController::class, 'deleteWebauthns'])->name('core::two_factor::webauthn::delete_webauthns');
    Route::post('/two-factor/get-yubikey', [YubikeyController::class, 'generateYubikey'])->name('core::two_factor::yubikey::generate_yubikey');
    Route::post('/two-factor/yubikey', [YubikeyController::class, 'activateYubikey'])->name('core::two_factor::yubikey::activate_yubikey');
    Route::put('/two-factor/yubikey', [YubikeyController::class, 'activateYubikey'])->name('core::two_factor::yubikey::activate_yubikey_put');
    Route::delete('/two-factor/yubikey', [YubikeyController::class, 'deleteYubikeys'])->name('core::two_factor::yubikey::delete_yubikeys');
    Route::post('/accounts/request-otp', [ProtectedActionsController::class, 'requestOtp'])->name('core::two_factor::protected_actions::request_otp');
    Route::post('/accounts/verify-otp', [ProtectedActionsController::class, 'verifyOtp'])->name('core::two_factor::protected_actions::verify_otp');

    // core::public
    Route::post('/public/organization/import', [PublicController::class, 'ldapImport'])->name('core::public::ldap_import');
});

// api::identity_routes()
Route::prefix('/identity')->group(function (): void {
    Route::post('/connect/token', [IdentityController::class, 'login'])->name('identity::login');
    Route::post('/accounts/prelogin', [IdentityController::class, 'postPrelogin'])->name('identity::post_prelogin');
    Route::post('/accounts/prelogin/password', [IdentityController::class, 'preloginPassword'])->name('identity::prelogin_password');
    Route::post('/accounts/register/send-verification-email', [IdentityController::class, 'registerVerificationEmail'])
        ->name('identity::register_verification_email');
    Route::post('/accounts/register/verification-email-clicked', [IdentityController::class, 'registerVerificationEmailClicked'])
        ->name('identity::register_verification_email_clicked');
    Route::post('/accounts/register/finish', [IdentityController::class, 'registerFinish'])->name('identity::register_finish');
    Route::get('/sso/prevalidate', [IdentityController::class, 'prevalidate'])->name('identity::prevalidate');
    // Both oidcsignin and oidcsignin_error.
    Route::get('/connect/oidc-signin', [IdentityController::class, 'oidcSignin'])->name('identity::oidcsignin');
    Route::get('/connect/authorize', [IdentityController::class, 'authorize'])->name('identity::authorize');
});

// api::icons_routes(): Vaultwarden's own icon service, or a redirect to the external ICON_SERVICE.
Route::prefix('/icons')->group(function (): void {
    if (IconsController::internal(app(Config::class))) {
        Route::get('/{host}/icon.png', [IconsController::class, 'iconInternal'])->name('icons::icon_internal');
    } else {
        Route::get('/{host}/icon.png', [IconsController::class, 'iconExternal'])->name('icons::icon_external');
    }
});

// api::core_events_routes()
Route::prefix('/events')->group(function (): void {
    Route::post('/collect', [EventsController::class, 'postEventsCollect'])->name('core::events::post_events_collect');
});

// api::notifications_routes(): the hubs, served by the notifications daemon.
if (app(Config::class)->bool('enable_websocket')) {
    Route::prefix('/notifications')->group(function (): void {
        Route::get('/hub', [NotificationsController::class, 'websocketsHub'])->name('notifications::websockets_hub');
        Route::get('/anonymous-hub', [NotificationsController::class, 'anonymousWebsocketsHub'])->name('notifications::anonymous_websockets_hub');
    });
}

// api::admin_routes(): without a token only the notice that the panel is disabled.
Route::prefix('/admin')->group(function (): void {
    if (! AdminController::enabled(app(Config::class))) {
        Route::get('/', [AdminController::class, 'adminDisabled'])->name('admin::admin_disabled');

        return;
    }

    Route::get('/', [AdminController::class, 'adminPage'])->name('admin::admin_page');
    Route::post('/', [AdminController::class, 'postAdminLogin'])->name('admin::post_admin_login');
    Route::get('/logout', [AdminController::class, 'logout'])->name('admin::logout');
    Route::post('/invite', [AdminController::class, 'inviteUser'])->name('admin::invite_user');
    Route::post('/test/smtp', [AdminController::class, 'testSmtp'])->name('admin::test_smtp');
    Route::post('/config', [AdminController::class, 'postConfig'])->name('admin::post_config');
    Route::post('/config/delete', [AdminController::class, 'deleteConfig'])->name('admin::delete_config');
    Route::post('/config/backup_db', [AdminController::class, 'backupDb'])->name('admin::backup_db');
    // Static segments before the user id, which Rocket ranks lower.
    Route::get('/users', [AdminController::class, 'getUsersJson'])->name('admin::get_users_json');
    Route::get('/users/overview', [AdminController::class, 'usersOverview'])->name('admin::users_overview');
    Route::get('/users/by-mail/{mail}', [AdminController::class, 'getUserByMailJson'])->name('admin::get_user_by_mail_json');
    Route::post('/users/org_type', [AdminController::class, 'updateMembershipType'])->name('admin::update_membership_type');
    Route::post('/users/update_revision', [AdminController::class, 'updateRevisionUsers'])->name('admin::update_revision_users');
    Route::get('/users/{userId}', [AdminController::class, 'getUserJson'])->name('admin::get_user_json');
    Route::post('/users/{userId}/delete', [AdminController::class, 'deleteUser'])->name('admin::delete_user');
    Route::delete('/users/{userId}/sso', [AdminController::class, 'deleteSsoUser'])->name('admin::delete_sso_user');
    Route::post('/users/{userId}/deauth', [AdminController::class, 'deauthUser'])->name('admin::deauth_user');
    Route::post('/users/{userId}/disable', [AdminController::class, 'disableUser'])->name('admin::disable_user');
    Route::post('/users/{userId}/enable', [AdminController::class, 'enableUser'])->name('admin::enable_user');
    Route::post('/users/{userId}/remove-2fa', [AdminController::class, 'remove2fa'])->name('admin::remove_2fa');
    Route::post('/users/{userId}/invite/resend', [AdminController::class, 'resendUserInvite'])->name('admin::resend_user_invite');
    Route::get('/organizations/overview', [AdminController::class, 'organizationsOverview'])->name('admin::organizations_overview');
    Route::post('/organizations/{orgId}/delete', [AdminController::class, 'deleteOrganization'])->name('admin::delete_organization');
    Route::get('/diagnostics', [AdminController::class, 'diagnostics'])->name('admin::diagnostics');
    Route::get('/diagnostics/config', [AdminController::class, 'getDiagnosticsConfig'])->name('admin::get_diagnostics_config');
    Route::get('/diagnostics/http', [AdminController::class, 'getDiagnosticsHttp'])->name('admin::get_diagnostics_http');
});
