<?php

namespace Tests\Unit\Config;

use App\Config\SettingDocs;
use App\Config\Settings;
use App\Parity\Matrix;
use Closure;
use PHPUnit\Framework\TestCase;
use Tests\Attributes\Parity;

/**
 * The hand-written catalogue against make_config! as extracted into the matrix.
 */
#[Parity('config:*')]
class SettingsTest extends TestCase
{
    public function test_every_setting_of_vaultwarden_is_defined_in_the_same_order(): void
    {
        $expected = array_map(
            static fn (array $item): string => Matrix::string($item['env'] ?? null),
            array_values(array_filter(self::matrix(), static fn (array $item): bool => ! isset($item['upstream']))),
        );

        $this->assertSame($expected, array_values(array_map(
            static fn ($setting): string => $setting->env(),
            Settings::all(),
        )));
    }

    public function test_type_group_editability_and_kind_of_default_match(): void
    {
        foreach (self::matrix() as $item) {
            $setting = Settings::all()[strtolower(Matrix::string($item['env'] ?? null))];

            $this->assertSame(
                [$item['type'] ?? null, $item['group'] ?? null, $item['editable'] ?? null, $item['default_kind'] ?? null],
                [$setting->type->value, $setting->group, $setting->editable, $setting->action],
                $setting->env(),
            );
        }
    }

    public function test_literal_defaults_match(): void
    {
        $checked = 0;
        foreach (self::matrix() as $item) {
            if (($item['default_kind'] ?? null) !== 'def') {
                continue;
            }

            $setting = Settings::all()[strtolower(Matrix::string($item['env'] ?? null))];
            $this->assertNotInstanceOf(Closure::class, $setting->default, $setting->env());
            $this->assertSame(self::rustLiteral(Matrix::string($item['default'] ?? null)), $setting->default, $setting->env());
            $checked++;
        }

        $this->assertSame(110, $checked);
    }

    public function test_computed_defaults_are_closures(): void
    {
        foreach (Settings::all() as $setting) {
            $this->assertSame(
                in_array($setting->action, ['auto', 'generated'], true),
                $setting->default instanceof Closure,
                $setting->env(),
            );
        }
    }

    /**
     * The admin panel shows the name and description of each doc comment.
     */
    public function test_documentation_matches(): void
    {
        $this->assertSame(array_keys(Settings::all()), array_keys(SettingDocs::SETTINGS));
        foreach (self::matrix() as $item) {
            $name = strtolower(Matrix::string($item['env'] ?? null));
            $this->assertSame([$item['title'] ?? '', $item['description'] ?? ''], SettingDocs::SETTINGS[$name], $name);
        }

        $groups = array_values(array_unique(array_map(static fn ($setting): string => $setting->group, Settings::all())));
        $this->assertSame($groups, array_keys(SettingDocs::GROUPS));
        foreach (SettingDocs::GROUPS as [$toggle]) {
            $this->assertTrue($toggle === '' || isset(Settings::all()[$toggle]), $toggle);
        }
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function matrix(): array
    {
        return array_values(array_filter(
            Matrix::load(dirname(__DIR__, 3).'/parity/matrix.json')->items,
            static fn (array $item): bool => ($item['kind'] ?? null) === 'config',
        ));
    }

    /**
     * The value of a Rust literal like `"data".to_owned()`, `String::new()`, `30_000` or `true`.
     */
    private static function rustLiteral(string $expression): string|int|bool
    {
        return match (true) {
            $expression === 'String::new()' => '',
            $expression === 'true' => true,
            $expression === 'false' => false,
            (bool) preg_match('/^"(.*)"\.to_owned\(\)$/', $expression, $match) => $match[1],
            (bool) preg_match('/^[0-9_]+$/', $expression) => (int) str_replace('_', '', $expression),
            default => throw new \RuntimeException("Unknown Rust literal {$expression}."),
        };
    }
}
