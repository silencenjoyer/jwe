<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Util\Base64Url;

class Base64UrlTest extends TestCase
{
    public function testEncodeEmptyStringReturnsEmptyString(): void
    {
        $this->assertSame('', Base64Url::encode(''));
    }

    public function testEncodeKnownVector(): void
    {
        $this->assertSame('SGVsbG8', Base64Url::encode('Hello'));
    }

    public function testEncodePlusAndSlashAreReplaced(): void
    {
        $result = Base64Url::encode("\xfb\xff");

        $this->assertSame('-_8', $result);
        $this->assertStringNotContainsString('+', $result);
        $this->assertStringNotContainsString('/', $result);
    }

    public function testEncodePaddingIsStripped(): void
    {
        $this->assertSame('YQ', Base64Url::encode('a'));
        $this->assertStringNotContainsString('=', Base64Url::encode('a'));
    }

    public function testDecodeKnownVector(): void
    {
        $this->assertSame('Hello', Base64Url::decode('SGVsbG8'));
    }

    public function testDecodeHandlesDashAndUnderscore(): void
    {
        $this->assertSame("\xfb\xff", Base64Url::decode('-_8'));
    }

    public function testRoundtrip(): void
    {
        $input = 'The quick brown fox';
        $this->assertSame($input, Base64Url::decode(Base64Url::encode($input)));
    }

    public function testRoundtripWithBinaryData(): void
    {
        $input = "\x00\x01\x02\xff\xfe\xfd";
        $this->assertSame($input, Base64Url::decode(Base64Url::encode($input)));
    }
}
