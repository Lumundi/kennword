<?php

namespace App\Icons;

/**
 * The HTML tokenizer of html5gum 0.9.0 (src/machine.rs and its helpers),
 * driving the FaviconEmitter of src/api/icons.rs over raw bytes, the way
 * get_favicons_node reads a page.
 *
 * Every state of the WHATWG tokenizer is here with html5gum's transitions,
 * including where it runs the next state at once (inline_next_state):
 * the emitter hands out its tokens between two steps, so the steps must be
 * the same. What the emitter ignores (text, comments, doctypes, errors) is
 * not produced.
 */
final class HtmlTokenizer
{
    public const string DATA = 'data';

    public const string RC_DATA = 'rcData';

    public const string RAW_TEXT = 'rawText';

    public const string SCRIPT_DATA = 'scriptData';

    public const string PLAIN_TEXT = 'plainText';

    /**
     * ControlToken::Continue; a string is ControlToken::SwitchTo.
     */
    private const int CONTINUE = 0;

    private const int EOF = 1;

    private const string WHITESPACE = "\t\n\x0C ";

    private int $position = 0;

    private readonly int $length;

    private bool $lastCharacterWasCr = false;

    /**
     * ReadHelper::to_reconsume: false for nothing, null for the end of the input.
     */
    private string|false|null $toReconsume = false;

    private bool $eof = false;

    private string $state = self::DATA;

    /**
     * @var array{string, bool}|null The state to return to and whether the reference is in an attribute
     */
    private ?array $returnState = null;

    private string $temporaryBuffer = '';

    private int $characterReferenceCode = 0;

    public function __construct(
        private readonly string $input,
        private readonly FaviconEmitter $emitter = new FaviconEmitter,
    ) {
        $this->length = strlen($input);
    }

    /**
     * Tokenizer::next.
     *
     * @return array{name: string, attributes: array<array-key, string>, closing: bool}|null
     */
    public function next(): ?array
    {
        while (true) {
            $token = $this->emitter->popToken();
            if ($token !== null) {
                return $token;
            }
            if ($this->eof) {
                return null;
            }
            $control = $this->run($this->state);
            if ($control === self::EOF) {
                $this->eof = true;
            } elseif (is_string($control)) {
                $this->state = $control;
            }
        }
    }

    private function run(string $state): int|string
    {
        return match ($state) {
            'data' => $this->data(),
            'rcData' => $this->rcData(),
            'rawText' => $this->rawText(),
            'scriptData' => $this->scriptData(),
            'plainText' => $this->plainText(),
            'tagOpen' => $this->tagOpen(),
            'endTagOpen' => $this->endTagOpen(),
            'tagName' => $this->tagName(),
            'rcDataLessThanSign' => $this->rcDataLessThanSign(),
            'rcDataEndTagOpen' => $this->rcDataEndTagOpen(),
            'rcDataEndTagName' => $this->rcDataEndTagName(),
            'rawTextLessThanSign' => $this->rawTextLessThanSign(),
            'rawTextEndTagOpen' => $this->rawTextEndTagOpen(),
            'rawTextEndTagName' => $this->rawTextEndTagName(),
            'scriptDataLessThanSign' => $this->scriptDataLessThanSign(),
            'scriptDataEndTagOpen' => $this->scriptDataEndTagOpen(),
            'scriptDataEndTagName' => $this->scriptDataEndTagName(),
            'scriptDataEscapeStart' => $this->scriptDataEscapeStart(),
            'scriptDataEscapeStartDash' => $this->scriptDataEscapeStartDash(),
            'scriptDataEscaped' => $this->scriptDataEscaped(),
            'scriptDataEscapedDash' => $this->scriptDataEscapedDash(),
            'scriptDataEscapedDashDash' => $this->scriptDataEscapedDashDash(),
            'scriptDataEscapedLessThanSign' => $this->scriptDataEscapedLessThanSign(),
            'scriptDataEscapedEndTagOpen' => $this->scriptDataEscapedEndTagOpen(),
            'scriptDataEscapedEndTagName' => $this->scriptDataEscapedEndTagName(),
            'scriptDataDoubleEscapeStart' => $this->scriptDataDoubleEscapeStart(),
            'scriptDataDoubleEscaped' => $this->scriptDataDoubleEscaped(),
            'scriptDataDoubleEscapedDash' => $this->scriptDataDoubleEscapedDash(),
            'scriptDataDoubleEscapedDashDash' => $this->scriptDataDoubleEscapedDashDash(),
            'scriptDataDoubleEscapedLessThanSign' => $this->scriptDataDoubleEscapedLessThanSign(),
            'scriptDataDoubleEscapeEnd' => $this->scriptDataDoubleEscapeEnd(),
            'beforeAttributeName' => $this->beforeAttributeName(),
            'attributeName' => $this->attributeName(),
            'afterAttributeName' => $this->afterAttributeName(),
            'beforeAttributeValue' => $this->beforeAttributeValue(),
            'attributeValueDoubleQuoted' => $this->attributeValueDoubleQuoted(),
            'attributeValueSingleQuoted' => $this->attributeValueSingleQuoted(),
            'attributeValueUnquoted' => $this->attributeValueUnquoted(),
            'afterAttributeValueQuoted' => $this->afterAttributeValueQuoted(),
            'selfClosingStartTag' => $this->selfClosingStartTag(),
            'bogusComment' => $this->bogusComment(),
            'markupDeclarationOpen' => $this->markupDeclarationOpen(),
            'commentStart' => $this->commentStart(),
            'commentStartDash' => $this->commentStartDash(),
            'comment' => $this->comment(),
            'commentLessThanSign' => $this->commentLessThanSign(),
            'commentLessThanSignBang' => $this->commentLessThanSignBang(),
            'commentLessThanSignBangDash' => $this->commentLessThanSignBangDash(),
            'commentLessThanSignBangDashDash' => $this->commentLessThanSignBangDashDash(),
            'commentEndDash' => $this->commentEndDash(),
            'commentEnd' => $this->commentEnd(),
            'commentEndBang' => $this->commentEndBang(),
            'doctype' => $this->doctype(),
            'beforeDoctypeName' => $this->beforeDoctypeName(),
            'doctypeName' => $this->doctypeName(),
            'afterDoctypeName' => $this->afterDoctypeName(),
            'afterDoctypePublicKeyword' => $this->afterDoctypePublicKeyword(),
            'afterDoctypeSystemKeyword' => $this->afterDoctypeSystemKeyword(),
            'beforeDoctypePublicIdentifier' => $this->beforeDoctypePublicIdentifier(),
            'beforeDoctypeSystemIdentifier' => $this->beforeDoctypeSystemIdentifier(),
            'doctypePublicIdentifierDoubleQuoted' => $this->doctypePublicIdentifierDoubleQuoted(),
            'doctypePublicIdentifierSingleQuoted' => $this->doctypePublicIdentifierSingleQuoted(),
            'doctypeSystemIdentifierDoubleQuoted' => $this->doctypeSystemIdentifierDoubleQuoted(),
            'doctypeSystemIdentifierSingleQuoted' => $this->doctypeSystemIdentifierSingleQuoted(),
            'afterDoctypePublicIdentifier' => $this->afterDoctypePublicIdentifier(),
            'betweenDoctypePublicAndSystemIdentifiers' => $this->betweenDoctypePublicAndSystemIdentifiers(),
            'afterDoctypeSystemIdentifier' => $this->afterDoctypeSystemIdentifier(),
            'bogusDoctype' => $this->bogusDoctype(),
            'characterReference' => $this->characterReference(),
            'namedCharacterReference' => $this->namedCharacterReference(),
            'ambiguousAmpersand' => $this->ambiguousAmpersand(),
            'numericCharacterReference' => $this->numericCharacterReference(),
            'hexadecimalCharacterReferenceStart' => $this->hexadecimalCharacterReferenceStart(),
            'hexadecimalCharacterReference' => $this->hexadecimalCharacterReference(),
            'decimalCharacterReference' => $this->decimalCharacterReference(),
            'numericCharacterReferenceEnd' => $this->numericCharacterReferenceEnd(),
            default => throw new \LogicException("Unknown tokenizer state {$state}"),
        };
    }

    /**
     * ControlToken::inline_next_state: switch and run the next state in the same step.
     */
    private function inline(string $state): int|string
    {
        $this->state = $state;

        return $this->run($state);
    }

    private function emitCurrentTagAndSwitch(): int
    {
        $this->state = $this->emitter->emitCurrentTag() ?? self::DATA;

        return self::CONTINUE;
    }

    private function initAttributeAndReconsume(string $c): string
    {
        $this->emitter->initAttribute();

        return $this->reconsumeIn($c, 'attributeName');
    }

    private function enterState(string $state, bool $isAttribute): int
    {
        $this->returnState = [$this->state, $isAttribute];
        $this->state = $state;

        return self::CONTINUE;
    }

    private function popReturnState(): string
    {
        $state = $this->returnState[0] ?? self::DATA;
        $this->returnState = null;

        return $state;
    }

    private function reconsumeIn(?string $c, string $state): string
    {
        $this->toReconsume = $c;

        return $state;
    }

    private function reconsumeInReturnState(?string $c): string
    {
        $state = $this->popReturnState();
        $this->toReconsume = $c;

        return $state;
    }

    private function isConsumedAsPartOfAnAttribute(): bool
    {
        return $this->returnState !== null && $this->returnState[1];
    }

    private function flushCodePointsConsumedAsCharacterReference(): void
    {
        if ($this->isConsumedAsPartOfAnAttribute()) {
            $this->emitter->pushAttributeValue($this->temporaryBuffer);
        }
        $this->temporaryBuffer = '';
    }

    /**
     * ReadHelper::read_byte, with newlines normalized.
     */
    private function readByte(): ?string
    {
        if ($this->toReconsume !== false) {
            $c = $this->toReconsume;
            $this->toReconsume = false;

            return $c;
        }

        $c = $this->position < $this->length ? $this->input[$this->position++] : null;
        if ($this->lastCharacterWasCr && $c === "\n") {
            $c = $this->position < $this->length ? $this->input[$this->position++] : null;
        }
        if ($c === "\r") {
            $this->lastCharacterWasCr = true;
            $c = "\n";
        } else {
            $this->lastCharacterWasCr = false;
        }

        return $c;
    }

    /**
     * ReadHelper::read_until: either one of the needle's bytes, or a run of
     * other bytes. A carriage return always stops a run.
     */
    private function readUntil(string $needle): ?string
    {
        if ($this->toReconsume !== false) {
            $c = $this->toReconsume;
            $this->toReconsume = false;

            return $c;
        }
        if ($this->position >= $this->length) {
            $this->lastCharacterWasCr = false;

            return null;
        }

        $run = strcspn($this->input, $needle."\r", $this->position);
        $chunk = substr($this->input, $this->position, max($run, 1));
        $this->position += strlen($chunk);

        if ($chunk === "\r") {
            $this->lastCharacterWasCr = true;

            return "\n";
        }
        if ($this->lastCharacterWasCr && $chunk[0] === "\n") {
            $chunk = substr($chunk, 1);
        }
        $this->lastCharacterWasCr = false;

        return $chunk;
    }

    /**
     * ReadHelper::try_read_string: consume the string if the input continues with it.
     */
    private function tryReadString(string $s, bool $caseSensitive): bool
    {
        $backup = $this->toReconsume;
        if ($this->toReconsume !== false) {
            $c = $this->toReconsume;
            $this->toReconsume = false;
            if ($c !== null && ($c === $s[0] || (! $caseSensitive && strtolower($c) === strtolower($s[0])))) {
                $s = substr($s, 1);
            } else {
                $this->toReconsume = $backup;

                return false;
            }
        }

        $next = substr($this->input, $this->position, strlen($s));
        if ($s === '' || (strlen($next) === strlen($s) && ($caseSensitive ? $next === $s : strcasecmp($next, $s) === 0))) {
            $this->position += strlen($s);
            $this->lastCharacterWasCr = false;

            return true;
        }
        $this->toReconsume = $backup;

        return false;
    }

    private static function isAlpha(?string $c): bool
    {
        return $c !== null && ctype_alpha($c);
    }

    private static function isWhitespace(?string $c): bool
    {
        return $c !== null && strlen($c) === 1 && str_contains(self::WHITESPACE, $c);
    }

    private function data(): int|string
    {
        while (true) {
            $xs = $this->readUntil("&<\0");
            if ($xs === '&') {
                return $this->enterState('characterReference', false);
            }
            if ($xs === '<') {
                return $this->inline('tagOpen');
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function rcData(): int|string
    {
        while (true) {
            $xs = $this->readUntil("&<\0");
            if ($xs === '&') {
                return $this->enterState('characterReference', false);
            }
            if ($xs === '<') {
                return 'rcDataLessThanSign';
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function rawText(): int|string
    {
        while (true) {
            $xs = $this->readUntil("<\0");
            if ($xs === '<') {
                return 'rawTextLessThanSign';
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function scriptData(): int|string
    {
        while (true) {
            $xs = $this->readUntil("<\0");
            if ($xs === '<') {
                return 'scriptDataLessThanSign';
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function plainText(): int
    {
        while ($this->readUntil("\0") !== null) {
            // Everything up to the end is text.
        }

        return self::EOF;
    }

    private function tagOpen(): int|string
    {
        $c = $this->readByte();

        return match (true) {
            $c === '!' => 'markupDeclarationOpen',
            $c === '/' => $this->inline('endTagOpen'),
            self::isAlpha($c) => $this->startTag($c),
            $c === '?' => $this->reconsumeIn($c, 'bogusComment'),
            $c === null => self::EOF,
            default => $this->reconsumeIn($c, self::DATA),
        };
    }

    private function startTag(?string $c): int|string
    {
        $this->emitter->initStartTag();

        return $this->inline($this->reconsumeIn($c, 'tagName'));
    }

    private function endTagOpen(): int|string
    {
        $c = $this->readByte();
        if (self::isAlpha($c)) {
            $this->emitter->initEndTag();

            return $this->inline($this->reconsumeIn($c, 'tagName'));
        }

        return match ($c) {
            '>' => self::DATA,
            null => self::EOF,
            default => $this->reconsumeIn($c, 'bogusComment'),
        };
    }

    private function tagName(): int|string
    {
        while (true) {
            $xs = $this->readUntil("\t\n\x0C />\0");
            if ($xs === null) {
                return self::EOF;
            }
            if (self::isWhitespace($xs)) {
                return 'beforeAttributeName';
            }
            if ($xs === '/') {
                return 'selfClosingStartTag';
            }
            if ($xs === '>') {
                return $this->emitCurrentTagAndSwitch();
            }
            $this->emitter->pushTagName($xs === "\0" ? "\u{fffd}" : strtolower($xs));
        }
    }

    private function rcDataLessThanSign(): string
    {
        $c = $this->readByte();
        if ($c === '/') {
            $this->temporaryBuffer = '';

            return 'rcDataEndTagOpen';
        }

        return $this->reconsumeIn($c, self::RC_DATA);
    }

    private function rcDataEndTagOpen(): string
    {
        return $this->textEndTagOpen('rcDataEndTagName', self::RC_DATA);
    }

    private function rcDataEndTagName(): int|string
    {
        return $this->textEndTagName(self::RC_DATA);
    }

    private function rawTextLessThanSign(): string
    {
        $c = $this->readByte();
        if ($c === '/') {
            $this->temporaryBuffer = '';

            return 'rawTextEndTagOpen';
        }

        return $this->reconsumeIn($c, self::RAW_TEXT);
    }

    private function rawTextEndTagOpen(): string
    {
        return $this->textEndTagOpen('rawTextEndTagName', self::RAW_TEXT);
    }

    private function rawTextEndTagName(): int|string
    {
        return $this->textEndTagName(self::RAW_TEXT);
    }

    private function scriptDataLessThanSign(): string
    {
        $c = $this->readByte();
        if ($c === '/') {
            $this->temporaryBuffer = '';

            return 'scriptDataEndTagOpen';
        }
        if ($c === '!') {
            return 'scriptDataEscapeStart';
        }

        return $this->reconsumeIn($c, self::SCRIPT_DATA);
    }

    private function scriptDataEndTagOpen(): string
    {
        return $this->textEndTagOpen('scriptDataEndTagName', self::SCRIPT_DATA);
    }

    private function scriptDataEndTagName(): int|string
    {
        return $this->textEndTagName(self::SCRIPT_DATA);
    }

    /**
     * The end tag open states of RCDATA, RAWTEXT and script data.
     */
    private function textEndTagOpen(string $nameState, string $textState): string
    {
        $c = $this->readByte();
        if (self::isAlpha($c)) {
            $this->emitter->initEndTag();

            return $this->reconsumeIn($c, $nameState);
        }

        return $this->reconsumeIn($c, $textState);
    }

    /**
     * The end tag name states of RCDATA, RAWTEXT and script data, which only
     * end the text with the start tag's own end tag.
     */
    private function textEndTagName(string $textState): int|string
    {
        while (true) {
            $c = $this->readByte();
            if (self::isWhitespace($c) && $this->emitter->currentIsAppropriateEndTagToken()) {
                return 'beforeAttributeName';
            }
            if ($c === '/' && $this->emitter->currentIsAppropriateEndTagToken()) {
                return 'selfClosingStartTag';
            }
            if ($c === '>' && $this->emitter->currentIsAppropriateEndTagToken()) {
                return $this->emitCurrentTagAndSwitch();
            }
            if (self::isAlpha($c)) {
                $this->emitter->pushTagName(strtolower((string) $c));
                $this->temporaryBuffer .= $c;

                continue;
            }
            $this->temporaryBuffer = '';

            return $this->reconsumeIn($c, $textState);
        }
    }

    private function scriptDataEscapeStart(): string
    {
        $c = $this->readByte();

        return $c === '-' ? 'scriptDataEscapeStartDash' : $this->reconsumeIn($c, self::SCRIPT_DATA);
    }

    private function scriptDataEscapeStartDash(): string
    {
        $c = $this->readByte();

        return $c === '-' ? 'scriptDataEscapedDashDash' : $this->reconsumeIn($c, self::SCRIPT_DATA);
    }

    private function scriptDataEscaped(): int|string
    {
        while (true) {
            $xs = $this->readUntil("-<\0");
            if ($xs === '-') {
                return 'scriptDataEscapedDash';
            }
            if ($xs === '<') {
                return 'scriptDataEscapedLessThanSign';
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function scriptDataEscapedDash(): int|string
    {
        return match ($this->readByte()) {
            '-' => 'scriptDataEscapedDashDash',
            '<' => 'scriptDataEscapedLessThanSign',
            null => self::EOF,
            default => 'scriptDataEscaped',
        };
    }

    private function scriptDataEscapedDashDash(): int|string
    {
        do {
            $c = $this->readByte();
        } while ($c === '-');

        return match ($c) {
            '<' => 'scriptDataEscapedLessThanSign',
            '>' => self::SCRIPT_DATA,
            null => self::EOF,
            default => 'scriptDataEscaped',
        };
    }

    private function scriptDataEscapedLessThanSign(): string
    {
        $c = $this->readByte();
        if ($c === '/') {
            $this->temporaryBuffer = '';

            return 'scriptDataEscapedEndTagOpen';
        }
        if (self::isAlpha($c)) {
            $this->temporaryBuffer = '';

            return $this->reconsumeIn($c, 'scriptDataDoubleEscapeStart');
        }

        return $this->reconsumeIn($c, 'scriptDataEscaped');
    }

    private function scriptDataEscapedEndTagOpen(): string
    {
        return $this->textEndTagOpen('scriptDataEscapedEndTagName', 'scriptDataEscaped');
    }

    private function scriptDataEscapedEndTagName(): int|string
    {
        return $this->textEndTagName('scriptDataEscaped');
    }

    private function scriptDataDoubleEscapeStart(): string
    {
        return $this->doubleEscapeBoundary('scriptDataDoubleEscaped', 'scriptDataEscaped', 'scriptDataEscaped');
    }

    private function scriptDataDoubleEscaped(): int|string
    {
        while (true) {
            $xs = $this->readUntil("-<\0");
            if ($xs === '-') {
                return 'scriptDataDoubleEscapedDash';
            }
            if ($xs === '<') {
                return 'scriptDataDoubleEscapedLessThanSign';
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function scriptDataDoubleEscapedDash(): int|string
    {
        return match ($this->readByte()) {
            '-' => 'scriptDataDoubleEscapedDashDash',
            '<' => 'scriptDataDoubleEscapedLessThanSign',
            null => self::EOF,
            default => 'scriptDataDoubleEscaped',
        };
    }

    private function scriptDataDoubleEscapedDashDash(): int|string
    {
        do {
            $c = $this->readByte();
        } while ($c === '-');

        return match ($c) {
            '<' => 'scriptDataDoubleEscapedLessThanSign',
            '>' => self::SCRIPT_DATA,
            null => self::EOF,
            default => 'scriptDataDoubleEscaped',
        };
    }

    private function scriptDataDoubleEscapedLessThanSign(): string
    {
        $c = $this->readByte();
        if ($c === '/') {
            $this->temporaryBuffer = '';

            return 'scriptDataDoubleEscapeEnd';
        }

        return $this->reconsumeIn($c, 'scriptDataDoubleEscaped');
    }

    private function scriptDataDoubleEscapeEnd(): string
    {
        return $this->doubleEscapeBoundary('scriptDataEscaped', 'scriptDataDoubleEscaped', 'scriptDataDoubleEscaped');
    }

    /**
     * The double escape start and end states: a tag name of "script" switches between escaped and double escaped.
     */
    private function doubleEscapeBoundary(string $ifScript, string $otherwise, string $reconsumeState): string
    {
        while (true) {
            $c = $this->readByte();
            if ($c !== null && str_contains(self::WHITESPACE.'/>', $c)) {
                return $this->temporaryBuffer === 'script' ? $ifScript : $otherwise;
            }
            if (self::isAlpha($c)) {
                $this->temporaryBuffer .= strtolower((string) $c);

                continue;
            }

            return $this->reconsumeIn($c, $reconsumeState);
        }
    }

    private function beforeAttributeName(): int|string
    {
        while (true) {
            $c = $this->readByte();
            if (self::isWhitespace($c)) {
                continue;
            }
            if ($c === '/' || $c === '>' || $c === null) {
                return $this->inline($this->reconsumeIn($c, 'afterAttributeName'));
            }
            if ($c === '=') {
                $this->emitter->initAttribute();
                $this->emitter->pushAttributeName('=');

                return 'attributeName';
            }
            $this->emitter->initAttribute();

            return $this->inline($this->reconsumeIn($c, 'attributeName'));
        }
    }

    private function attributeName(): int|string
    {
        while (true) {
            $xs = $this->readUntil("\t\n\x0C />=\0\"'<");
            if ($xs === null) {
                return $this->reconsumeIn(null, 'afterAttributeName');
            }
            // In the same step since 0.9.0: before the emitter hands out a base tag that init_attribute flagged.
            if (self::isWhitespace($xs) || $xs === '/' || $xs === '>') {
                return $this->inline($this->reconsumeIn($xs, 'afterAttributeName'));
            }
            if ($xs === '=') {
                return $this->inline('beforeAttributeValue');
            }
            $this->emitter->pushAttributeName(match ($xs) {
                "\0" => "\u{fffd}",
                '"', "'", '<' => $xs,
                default => strtolower($xs),
            });
        }
    }

    private function afterAttributeName(): int|string
    {
        while (true) {
            $c = $this->readByte();
            if (self::isWhitespace($c)) {
                continue;
            }

            if ($c === null) {
                return self::EOF;
            }

            return match ($c) {
                '/' => 'selfClosingStartTag',
                '=' => 'beforeAttributeValue',
                '>' => $this->emitCurrentTagAndSwitch(),
                default => $this->initAttributeAndReconsume($c),
            };
        }
    }

    private function beforeAttributeValue(): int|string
    {
        while (true) {
            $c = $this->readByte();
            if (self::isWhitespace($c)) {
                continue;
            }

            return match ($c) {
                '"' => $this->inline('attributeValueDoubleQuoted'),
                "'" => 'attributeValueSingleQuoted',
                '>' => $this->emitCurrentTagAndSwitch(),
                default => $this->reconsumeIn($c, 'attributeValueUnquoted'),
            };
        }
    }

    private function attributeValueDoubleQuoted(): int|string
    {
        while (true) {
            $xs = $this->readUntil("\"&\0");
            if ($xs === null) {
                return self::EOF;
            }
            if ($xs === '"') {
                return $this->inline('afterAttributeValueQuoted');
            }
            if ($xs === '&') {
                return $this->enterState('characterReference', true);
            }
            $this->emitter->pushAttributeValue($xs === "\0" ? "\u{fffd}" : $xs);
        }
    }

    private function attributeValueSingleQuoted(): int|string
    {
        while (true) {
            $xs = $this->readUntil("'&\0");
            if ($xs === null) {
                return self::EOF;
            }
            if ($xs === "'") {
                return 'afterAttributeValueQuoted';
            }
            if ($xs === '&') {
                return $this->enterState('characterReference', true);
            }
            $this->emitter->pushAttributeValue($xs === "\0" ? "\u{fffd}" : $xs);
        }
    }

    private function attributeValueUnquoted(): int|string
    {
        while (true) {
            $xs = $this->readUntil("\t\n\x0C &>\0\"'<=`");
            if ($xs === null) {
                return self::EOF;
            }
            if (self::isWhitespace($xs)) {
                return 'beforeAttributeName';
            }
            if ($xs === '&') {
                return $this->enterState('characterReference', true);
            }
            if ($xs === '>') {
                return $this->emitCurrentTagAndSwitch();
            }
            $this->emitter->pushAttributeValue($xs === "\0" ? "\u{fffd}" : $xs);
        }
    }

    private function afterAttributeValueQuoted(): int|string
    {
        $c = $this->readByte();
        if ($c === null || str_contains(self::WHITESPACE.'/>', $c)) {
            return $this->inline($this->reconsumeIn($c, 'beforeAttributeName'));
        }

        return $this->reconsumeIn($c, 'beforeAttributeName');
    }

    private function selfClosingStartTag(): int|string
    {
        $c = $this->readByte();

        return match ($c) {
            '>' => $this->emitCurrentTagAndSwitch(),
            null => self::EOF,
            default => $this->reconsumeIn($c, 'beforeAttributeName'),
        };
    }

    private function bogusComment(): int|string
    {
        while (true) {
            $xs = $this->readUntil(">\0");
            if ($xs === '>') {
                return self::DATA;
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function markupDeclarationOpen(): string
    {
        $c = $this->readByte();
        if ($c === '-' && $this->tryReadString('-', true)) {
            return 'commentStart';
        }
        if (($c === 'd' || $c === 'D') && $this->tryReadString('octype', false)) {
            return 'doctype';
        }
        if ($c === '[' && $this->tryReadString('CDATA[', true)) {
            // There is no foreign content without a tree builder: a bogus comment.
            return 'bogusComment';
        }

        return $this->reconsumeIn($c, 'bogusComment');
    }

    private function commentStart(): string
    {
        $c = $this->readByte();

        return match ($c) {
            '-' => 'commentStartDash',
            '>' => self::DATA,
            default => $this->reconsumeIn($c, 'comment'),
        };
    }

    private function commentStartDash(): int|string
    {
        $c = $this->readByte();

        return match ($c) {
            '-' => 'commentEnd',
            '>' => self::DATA,
            null => self::EOF,
            default => $this->reconsumeIn($c, 'comment'),
        };
    }

    private function comment(): int|string
    {
        while (true) {
            $xs = $this->readUntil("<-\0");
            if ($xs === '<') {
                return 'commentLessThanSign';
            }
            if ($xs === '-') {
                return 'commentEndDash';
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function commentLessThanSign(): string
    {
        while (true) {
            $c = $this->readByte();
            if ($c === '!') {
                return 'commentLessThanSignBang';
            }
            if ($c !== '<') {
                return $this->reconsumeIn($c, 'comment');
            }
        }
    }

    private function commentLessThanSignBang(): string
    {
        $c = $this->readByte();

        return $c === '-' ? 'commentLessThanSignBangDash' : $this->reconsumeIn($c, 'comment');
    }

    private function commentLessThanSignBangDash(): string
    {
        $c = $this->readByte();

        return $c === '-' ? 'commentLessThanSignBangDashDash' : $this->reconsumeIn($c, 'commentEndDash');
    }

    private function commentLessThanSignBangDashDash(): string
    {
        return $this->reconsumeIn($this->readByte(), 'commentEnd');
    }

    private function commentEndDash(): int|string
    {
        $c = $this->readByte();

        return match ($c) {
            '-' => 'commentEnd',
            null => self::EOF,
            default => $this->reconsumeIn($c, 'comment'),
        };
    }

    private function commentEnd(): int|string
    {
        do {
            $c = $this->readByte();
        } while ($c === '-');

        return match ($c) {
            '>' => self::DATA,
            '!' => 'commentEndBang',
            null => self::EOF,
            default => $this->reconsumeIn($c, 'comment'),
        };
    }

    private function commentEndBang(): int|string
    {
        $c = $this->readByte();

        return match ($c) {
            '-' => 'commentEndDash',
            '>' => self::DATA,
            null => self::EOF,
            default => $this->reconsumeIn($c, 'comment'),
        };
    }

    private function doctype(): int|string
    {
        $c = $this->readByte();
        if (self::isWhitespace($c)) {
            return 'beforeDoctypeName';
        }

        return $c === null ? self::EOF : $this->reconsumeIn($c, 'beforeDoctypeName');
    }

    private function beforeDoctypeName(): int|string
    {
        while (true) {
            $c = $this->readByte();
            if (self::isWhitespace($c)) {
                continue;
            }

            return match ($c) {
                '>' => self::DATA,
                null => self::EOF,
                default => 'doctypeName',
            };
        }
    }

    private function doctypeName(): int|string
    {
        while (true) {
            $xs = $this->readUntil("\t\n\x0C >\0");
            if (self::isWhitespace($xs)) {
                return 'afterDoctypeName';
            }
            if ($xs === '>') {
                return self::DATA;
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function afterDoctypeName(): int|string
    {
        while (true) {
            $c = $this->readByte();
            if (self::isWhitespace($c)) {
                continue;
            }
            if ($c === '>') {
                return self::DATA;
            }
            if ($c === null) {
                return self::EOF;
            }
            if (($c === 'p' || $c === 'P') && $this->tryReadString('ublic', false)) {
                return 'afterDoctypePublicKeyword';
            }
            if (($c === 's' || $c === 'S') && $this->tryReadString('ystem', false)) {
                return 'afterDoctypeSystemKeyword';
            }

            return $this->reconsumeIn($c, 'bogusDoctype');
        }
    }

    private function afterDoctypePublicKeyword(): int|string
    {
        return $this->afterDoctypeKeyword('beforeDoctypePublicIdentifier', 'doctypePublicIdentifierDoubleQuoted', 'doctypePublicIdentifierSingleQuoted');
    }

    private function afterDoctypeSystemKeyword(): int|string
    {
        return $this->afterDoctypeKeyword('beforeDoctypeSystemIdentifier', 'doctypeSystemIdentifierDoubleQuoted', 'doctypeSystemIdentifierSingleQuoted');
    }

    private function afterDoctypeKeyword(string $whitespaceState, string $doubleQuoted, string $singleQuoted): int|string
    {
        $c = $this->readByte();
        if (self::isWhitespace($c)) {
            return $whitespaceState;
        }

        return match ($c) {
            '"' => $doubleQuoted,
            "'" => $singleQuoted,
            '>' => self::DATA,
            null => self::EOF,
            default => $this->reconsumeIn($c, 'bogusDoctype'),
        };
    }

    private function beforeDoctypePublicIdentifier(): int|string
    {
        return $this->beforeDoctypeIdentifier('doctypePublicIdentifierDoubleQuoted', 'doctypePublicIdentifierSingleQuoted');
    }

    private function beforeDoctypeSystemIdentifier(): int|string
    {
        return $this->beforeDoctypeIdentifier('doctypeSystemIdentifierDoubleQuoted', 'doctypeSystemIdentifierSingleQuoted');
    }

    private function beforeDoctypeIdentifier(string $doubleQuoted, string $singleQuoted): int|string
    {
        while (true) {
            $c = $this->readByte();
            if (self::isWhitespace($c)) {
                continue;
            }

            return match ($c) {
                '"' => $doubleQuoted,
                "'" => $singleQuoted,
                '>' => self::DATA,
                null => self::EOF,
                default => $this->reconsumeIn($c, 'bogusDoctype'),
            };
        }
    }

    private function doctypePublicIdentifierDoubleQuoted(): int|string
    {
        return $this->doctypeIdentifier('"', 'afterDoctypePublicIdentifier');
    }

    private function doctypePublicIdentifierSingleQuoted(): int|string
    {
        return $this->doctypeIdentifier("'", 'afterDoctypePublicIdentifier');
    }

    private function doctypeSystemIdentifierDoubleQuoted(): int|string
    {
        return $this->doctypeIdentifier('"', 'afterDoctypeSystemIdentifier');
    }

    private function doctypeSystemIdentifierSingleQuoted(): int|string
    {
        return $this->doctypeIdentifier("'", 'afterDoctypeSystemIdentifier');
    }

    private function doctypeIdentifier(string $quote, string $afterState): int|string
    {
        while (true) {
            $xs = $this->readUntil($quote.">\0");
            if ($xs === $quote) {
                return $afterState;
            }
            if ($xs === '>') {
                return self::DATA;
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function afterDoctypePublicIdentifier(): int|string
    {
        $c = $this->readByte();
        if (self::isWhitespace($c)) {
            return 'betweenDoctypePublicAndSystemIdentifiers';
        }

        return match ($c) {
            '>' => self::DATA,
            '"' => 'doctypeSystemIdentifierDoubleQuoted',
            "'" => 'doctypeSystemIdentifierSingleQuoted',
            null => self::EOF,
            default => $this->reconsumeIn($c, 'bogusDoctype'),
        };
    }

    private function betweenDoctypePublicAndSystemIdentifiers(): int|string
    {
        return $this->beforeDoctypeIdentifier('doctypeSystemIdentifierDoubleQuoted', 'doctypeSystemIdentifierSingleQuoted');
    }

    private function afterDoctypeSystemIdentifier(): int|string
    {
        while (true) {
            $c = $this->readByte();
            if (self::isWhitespace($c)) {
                continue;
            }

            return match ($c) {
                '>' => self::DATA,
                null => self::EOF,
                default => $this->reconsumeIn($c, 'bogusDoctype'),
            };
        }
    }

    private function bogusDoctype(): int|string
    {
        while (true) {
            $xs = $this->readUntil(">\0");
            if ($xs === '>') {
                return self::DATA;
            }
            if ($xs === null) {
                return self::EOF;
            }
        }
    }

    private function characterReference(): string
    {
        $this->temporaryBuffer = '&';
        $c = $this->readByte();
        if ($c !== null && ctype_alnum($c)) {
            return $this->reconsumeIn($c, 'namedCharacterReference');
        }
        if ($c === '#') {
            $this->temporaryBuffer .= '#';

            return 'numericCharacterReference';
        }
        $this->flushCodePointsConsumedAsCharacterReference();

        return $this->reconsumeInReturnState($c);
    }

    private function namedCharacterReference(): string
    {
        $c = $this->readByte();
        $name = null;
        if ($c !== null) {
            // The longest name that the input continues with.
            $rest = substr($this->input, $this->position, HtmlEntities::MAX_LENGTH - 1);
            for ($length = strlen($rest); $length >= 0 && $name === null; $length--) {
                $candidate = $c.substr($rest, 0, $length);
                if (isset(HtmlEntities::ALL[$candidate]) && ($length === 0 || $this->tryReadString(substr($rest, 0, $length), true))) {
                    $name = $candidate;
                }
            }
        }

        if ($name === null) {
            $this->flushCodePointsConsumedAsCharacterReference();

            return $this->reconsumeIn($c, 'ambiguousAmpersand');
        }

        $next = $this->readByte();
        if (! $this->isConsumedAsPartOfAnAttribute() || str_ends_with($name, ';') || ! ($next === '=' || ($next !== null && ctype_alnum($next)))) {
            $this->temporaryBuffer = HtmlEntities::ALL[$name];
        } else {
            $this->temporaryBuffer .= $name;
        }
        $this->flushCodePointsConsumedAsCharacterReference();

        return $this->reconsumeInReturnState($next);
    }

    private function ambiguousAmpersand(): string
    {
        while (true) {
            $c = $this->readByte();
            if ($c !== null && ctype_alnum($c)) {
                if ($this->isConsumedAsPartOfAnAttribute()) {
                    $this->emitter->pushAttributeValue($c);
                }

                continue;
            }

            return $this->reconsumeInReturnState($c);
        }
    }

    private function numericCharacterReference(): string
    {
        $this->characterReferenceCode = 0;
        $c = $this->readByte();
        if ($c === 'x' || $c === 'X') {
            $this->temporaryBuffer .= $c;

            return 'hexadecimalCharacterReferenceStart';
        }
        if ($c !== null && ctype_digit($c)) {
            return $this->reconsumeIn($c, 'decimalCharacterReference');
        }
        $this->flushCodePointsConsumedAsCharacterReference();

        return $this->reconsumeInReturnState($c);
    }

    private function hexadecimalCharacterReferenceStart(): string
    {
        $c = $this->readByte();
        if ($c !== null && ctype_xdigit($c)) {
            return $this->reconsumeIn($c, 'hexadecimalCharacterReference');
        }
        $this->flushCodePointsConsumedAsCharacterReference();

        return $this->reconsumeInReturnState($c);
    }

    private function hexadecimalCharacterReference(): string
    {
        return $this->numericReferenceDigits(16);
    }

    private function decimalCharacterReference(): string
    {
        return $this->numericReferenceDigits(10);
    }

    private function numericReferenceDigits(int $base): string
    {
        while (true) {
            $c = $this->readByte();
            if ($c !== null && ($base === 16 ? ctype_xdigit($c) : ctype_digit($c))) {
                // mutate_character_reference!: a u32 overflow makes it out of range.
                $code = $this->characterReferenceCode * $base + (int) hexdec($c);
                $this->characterReferenceCode = $code > 0xFFFFFFFF ? 0x110000 : $code;

                continue;
            }
            if ($c === ';') {
                return 'numericCharacterReferenceEnd';
            }

            return $this->reconsumeIn($c, 'numericCharacterReferenceEnd');
        }
    }

    private function numericCharacterReferenceEnd(): int
    {
        $code = $this->characterReferenceCode;
        if ($code === 0 || $code >= 0x110000 || ($code >= 0xD800 && $code <= 0xDFFF)) {
            $code = 0xFFFD;
        } elseif (($code <= 0x1F || ($code >= 0x7F && $code <= 0x9F)) && ! in_array($code, [0x09, 0x0A, 0x0C, 0x20], true)) {
            $code = [
                0x80 => 0x20AC, 0x82 => 0x201A, 0x83 => 0x0192, 0x84 => 0x201E, 0x85 => 0x2026, 0x86 => 0x2020,
                0x87 => 0x2021, 0x88 => 0x02C6, 0x89 => 0x2030, 0x8A => 0x0160, 0x8B => 0x2039, 0x8C => 0x0152,
                0x8E => 0x017D, 0x91 => 0x2018, 0x92 => 0x2019, 0x93 => 0x201C, 0x94 => 0x201D, 0x95 => 0x2022,
                0x96 => 0x2013, 0x97 => 0x2014, 0x98 => 0x02DC, 0x99 => 0x2122, 0x9A => 0x0161, 0x9B => 0x203A,
                0x9C => 0x0153, 0x9E => 0x017E, 0x9F => 0x0178,
            ][$code] ?? $code;
        }

        $this->temporaryBuffer = mb_chr($code, 'UTF-8') ?: '';
        $this->flushCodePointsConsumedAsCharacterReference();
        $this->state = $this->popReturnState();

        return self::CONTINUE;
    }
}
