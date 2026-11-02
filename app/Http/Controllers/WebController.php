<?php

namespace App\Http\Controllers;

use App\Auth\Jwt;
use App\Auth\JwtIssuer;
use App\Config\Config;
use App\Http\ApiError;
use App\Http\Cached;
use App\Http\Data\Query;
use App\Http\EmptyResponse;
use App\Http\EtagCached;
use App\Http\FileResponse;
use App\Http\HttpStatus;
use App\Http\Json;
use App\Http\Redirect;
use App\Models\Attachment;
use App\Support\Dates;
use App\Support\EscapeDebug;
use App\Support\Uuid;
use App\Support\WebVault;
use App\Templates\TemplateRenderer;
use Illuminate\Database\DatabaseManager;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use ScssPhp\ScssPhp\Compiler;
use ScssPhp\ScssPhp\OutputStyle;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Throwable;

/**
 * src/api/web.rs
 */
final readonly class WebController
{
    /**
     * STATIC_FILES: the images and scripts Vaultwarden embeds, by name, with
     * their folder in resources/vaultwarden/static and their content type.
     */
    private const array STATIC_FILES = [
        '404.png' => ['images', 'image/png'],
        'mail-github.png' => ['images', 'image/png'],
        'logo-gray.png' => ['images', 'image/png'],
        'error-x.svg' => ['images', 'image/svg+xml'],
        'hibp.png' => ['images', 'image/png'],
        'vaultwarden-icon.png' => ['images', 'image/png'],
        'vaultwarden-favicon.png' => ['images', 'image/png'],
        '404.css' => ['scripts', 'text/css; charset=utf-8'],
        'admin.css' => ['scripts', 'text/css; charset=utf-8'],
        'admin.js' => ['scripts', 'text/javascript'],
        'admin_settings.js' => ['scripts', 'text/javascript'],
        'admin_users.js' => ['scripts', 'text/javascript'],
        'admin_organizations.js' => ['scripts', 'text/javascript'],
        'admin_diagnostics.js' => ['scripts', 'text/javascript'],
        'bootstrap.css' => ['scripts', 'text/css; charset=utf-8'],
        'bootstrap.bundle.js' => ['scripts', 'text/javascript'],
        'jdenticon-3.3.0.js' => ['scripts', 'text/javascript'],
        'datatables.js' => ['scripts', 'text/javascript'],
        'datatables.css' => ['scripts', 'text/css; charset=utf-8'],
    ];

    public function __construct(
        private DatabaseManager $databases,
        private Jwt $jwt,
        private Config $config,
        private TemplateRenderer $templates,
    ) {}

    /**
     * GET /: the web vault's index.html.
     */
    public function webIndex(): FileResponse
    {
        return Cached::short($this->webVaultFile('index.html'), immutable: false);
    }

    /**
     * GET /index.html: to the domain path, which the web vault expects.
     */
    public function webIndexDirect(): Redirect
    {
        return new Redirect($this->config->string('domain_path').'/');
    }

    /**
     * HEAD /, for uptime monitors.
     */
    public function webIndexHead(): EmptyResponse
    {
        return new EmptyResponse;
    }

    /**
     * GET /app-id.json: the FIDO trusted facets, the web origin and the mobile apps.
     */
    public function appId(): Response
    {
        return Cached::long(Json::response(Json::sorted(['trustedFacets' => [[
            'version' => ['major' => 1, 'minor' => 0],
            'ids' => [$this->config->string('domain_origin'), 'ios:bundle-id:com.8bit.bitwarden', 'android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI'],
        ]]]), headers: ['Content-Type' => 'application/fido.trusted-apps+json']), immutable: true);
    }

    /**
     * GET /.well-known/apple-app-site-association: the iOS apps may use the passkeys of this domain.
     */
    public function appleAppSiteAssociation(): Response
    {
        return Cached::long(Json::response(['webcredentials' => ['apps' => ['LTZ2PFU5D6.com.8bit.bitwarden', 'LTZ2PFU5D6.com.8bit.bitwarden.beta']]]),
            immutable: true);
    }

    /**
     * GET /{p..}: any other file of the web vault, below every other route.
     */
    public function webFiles(Request $request): FileResponse
    {
        $base = $this->config->string('domain_path');
        $path = WebVault::relativePath(substr($request->getPathInfo(), strlen($base)));
        if ($path === null) {
            // The PathBuf guard forwards, and no route is left.
            throw new HttpStatus(422, 'Path is not a valid file path.');
        }

        return Cached::long($this->webVaultFile($path), immutable: true);
    }

    /**
     * GET /css/vaultwarden.css: the web vault's style changes, compiled from
     * the templates scss/vaultwarden.scss and scss/user.vaultwarden.scss.
     */
    public function vaultwardenCss(Request $request): EtagCached
    {
        $options = [
            'email_change_allowed' => $this->config->bool('email_change_allowed'),
            'emergency_access_allowed' => $this->config->bool('emergency_access_allowed'),
            'load_user_scss' => true,
            'mail_2fa_enabled' => $this->config->bool('_enable_email_2fa'),
            'mail_enabled' => $this->config->mailEnabled(),
            'sends_allowed' => $this->config->bool('sends_allowed'),
            'remember_2fa_disabled' => $this->config->bool('disable_2fa_remember'),
            'password_hints_allowed' => $this->config->bool('password_hints_allowed'),
            'signup_disabled' => $this->config->isSignupDisabled(),
            'sso_enabled' => $this->config->bool('sso_enabled'),
            'sso_only' => $this->config->bool('sso_enabled') && $this->config->bool('sso_only'),
            'webauthn_2fa_supported' => $this->config->isWebauthn2faSupported(),
            'yubico_enabled' => $this->config->bool('_enable_yubico') && $this->config->optionalString('yubico_client_id') !== null
                && $this->config->optionalString('yubico_secret_key') !== null,
        ];

        try {
            $scss = $this->templates->render('scss/vaultwarden.scss', $options);
        } catch (Throwable $error) {
            logger()->warning("Loading scss/vaultwarden.scss.hbs or scss/user.vaultwarden.scss.hbs failed. {$error->getMessage()}");
            $scss = $this->templates->renderFallback('scss/vaultwarden.scss', $options);
        }

        try {
            $css = self::compileScss($scss);
        } catch (Throwable $error) {
            logger()->warning("Compiling the Vaultwarden SCSS styles failed. {$error->getMessage()}");
            $css = self::compileScss($this->templates->renderFallback('scss/vaultwarden.scss', [...$options, 'load_user_scss' => false]));
        }

        return new EtagCached($request, $css, 'text/css; charset=utf-8', hash('sha256', $css));
    }

    /**
     * GET /attachments/{cipher_id}/{file_id}?token=: the file, for whoever has
     * the download token of the attachment. Anything else is a 404.
     */
    public function attachments(Request $request, string $cipherId, string $fileId): FileResponse
    {
        $cipherId = Uuid::parameter($request, $cipherId);
        $fileId = Uuid::idParameter($request, $fileId);
        // Without a token the request forwards to the web vault's catch-all.
        $token = Query::first($request, 'token') ?? throw new HttpStatus(404, 'No token.');

        try {
            $claims = $this->jwt->decode($token, JwtIssuer::FileDownload);
        } catch (ApiError) {
            throw new HttpStatus(404, 'Invalid token.');
        }
        if (($claims['sub'] ?? null) !== $cipherId || ($claims['file_id'] ?? null) !== $fileId) {
            throw new HttpStatus(404, 'The token is for another file.');
        }

        $path = Attachment::path($cipherId, $fileId);
        if (! is_file($path)) {
            throw new HttpStatus(404, 'No such file.');
        }

        return new FileResponse($path);
    }

    /**
     * GET /vw_static/{filename}: the embedded files, with an ETag of their SHA-256.
     *
     * @throws ApiError
     */
    public function staticFiles(Request $request, string $filename): EtagCached
    {
        [$folder, $contentType] = self::STATIC_FILES[$filename] ?? throw ApiError::message('Static file not found: '.EscapeDebug::of($filename));
        $content = (string) file_get_contents(resource_path("vaultwarden/static/{$folder}/{$filename}"));

        return new EtagCached($request, $content, $contentType, hash('sha256', $content));
    }

    /**
     * GET /alive
     */
    public function alive(): Response
    {
        $this->database();

        return Json::response(Dates::format(Dates::now()));
    }

    /**
     * HEAD /alive
     */
    public function aliveHead(): EmptyResponse
    {
        $this->database();

        return new EmptyResponse;
    }

    /**
     * Whether Vaultwarden mounts the web vault's routes and its 404 page.
     */
    public static function webVaultEnabled(Config $config): bool
    {
        return $config->bool('web_vault_enabled');
    }

    /**
     * grass_compiler::from_string with the compressed output style.
     */
    private static function compileScss(string $scss): string
    {
        $compiler = new Compiler;
        $compiler->setOutputStyle(OutputStyle::COMPRESSED);

        return $compiler->compileString($scss)->getCss();
    }

    /**
     * NamedFile::open in WEB_VAULT_FOLDER; a missing file is a 404.
     */
    private function webVaultFile(string $path): FileResponse
    {
        $file = rtrim($this->config->path('web_vault_folder'), '/').'/'.$path;
        // A NUL byte names no file; PHP's file functions would throw.
        if (str_contains($file, "\0") || ! is_file($file)) {
            throw new HttpStatus(404, 'No such file in the web vault.');
        }

        return new FileResponse($file, WebVault::contentType($file));
    }

    /**
     * The DbConn guard: without a database connection the request fails with 503.
     */
    private function database(): void
    {
        try {
            $this->databases->connection()->getPdo();
        } catch (Throwable $exception) {
            throw new HttpException(503, 'No database connection.', $exception);
        }
    }
}
