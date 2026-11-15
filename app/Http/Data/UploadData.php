<?php

namespace App\Http\Data;

use App\Http\HttpStatus;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;

/**
 * UploadData in src/api/core/ciphers.rs: a multipart form with an optional
 * `key` and the file in `data`, a Rocket TempFile.
 */
final readonly class UploadData
{
    private function __construct(
        public ?string $key,
        private ?UploadedFile $file,
        private ?string $text,
    ) {}

    /**
     * The routes only match multipart requests; Rocket finds no other route.
     *
     * @throws HttpStatus
     */
    public static function requireMultipart(Request $request): void
    {
        if (! str_starts_with(strtolower((string) $request->headers->get('Content-Type')), 'multipart/form-data')) {
            throw new HttpStatus(404, 'The route only takes multipart/form-data.');
        }
    }

    /**
     * @throws HttpStatus
     */
    public static function fromRequest(Request $request): self
    {
        $key = $request->request->get('key');
        // file() converts Symfony's uploads into Laravel's; the bag holds Symfony's.
        $file = $request->file('data');
        $text = $request->request->get('data');

        if ($file instanceof UploadedFile) {
            if (in_array($file->getError(), [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true)) {
                throw new HttpStatus(413, 'The file is larger than the upload limit.');
            }
            if ($file->getError() !== UPLOAD_ERR_OK) {
                throw new HttpStatus(400, 'The file did not arrive: '.$file->getErrorMessage());
            }

            return new self(is_string($key) ? $key : null, $file, null);
        }
        if (is_string($text)) {
            // A plain value makes a TempFile without a file name.
            return new self(is_string($key) ? $key : null, null, $text);
        }

        throw new HttpStatus(422, 'Missing field `data`.');
    }

    public function size(): int
    {
        return $this->file === null ? strlen((string) $this->text) : (int) $this->file->getSize();
    }

    /**
     * TempFile::raw_name, unsanitized: the encrypted file name. PHP cuts the
     * name at the last slash, which base64 contains; its full path is whole.
     * multer drops a file name that is not UTF-8, so there is none then.
     */
    public function rawName(): ?string
    {
        $name = $this->file?->getClientOriginalPath();

        return $name !== null && mb_check_encoding($name, 'UTF-8') ? $name : null;
    }

    /**
     * util::save_temp_file, overwriting what is there.
     */
    public function store(string $path): void
    {
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0777, true);
        }

        if ($this->file === null) {
            file_put_contents($path, (string) $this->text);
        } else {
            $this->file->move(dirname($path), basename($path));
        }
    }
}
