<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Keys\Key;

class KeyTest extends TestCase
{
    private string $content;
    private string $tempPath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->content  = 'my-secret-key-content';
        $this->tempPath = tempnam(sys_get_temp_dir(), 'key_test_');
        file_put_contents($this->tempPath, $this->content);
    }

    protected function tearDown(): void
    {
        @unlink($this->tempPath);
    }

    public function testFromContentAsContentRoundtrip(): void
    {
        $this->assertSame($this->content, Key::fromContent($this->content)->asContent());
    }

    public function testFromContentGetPathReturnsTempStream(): void
    {
        $this->assertSame('php://temp', Key::fromContent($this->content)->getPath());
    }

    public function testFromPathAsContentReturnsFileContents(): void
    {
        $this->assertSame($this->content, Key::fromPath($this->tempPath)->asContent());
    }

    public function testFromPathGetPathReturnsOriginalPath(): void
    {
        $this->assertSame($this->tempPath, Key::fromPath($this->tempPath)->getPath());
    }

    public function testToStringReturnsKeyContent(): void
    {
        $this->assertSame($this->content, (string) Key::fromContent($this->content));
    }

    public function testAsResourceReturnsValidResource(): void
    {
        $resource = Key::fromPath($this->tempPath)->asResource();
        $this->assertIsResource($resource);
        fclose($resource);
    }

    public function testAsResourceThrowsRuntimeExceptionOnInvalidPath(): void
    {
        $key = Key::fromPath($this->tempPath);
        unlink($this->tempPath);

        $this->expectException(RuntimeException::class);

        set_error_handler(static function (): bool { return true; }, E_WARNING);
        try {
            $key->asResource();
        } finally {
            restore_error_handler();
        }
    }

    public function testDebugInfoMasksKeyData(): void
    {
        $info = Key::fromContent($this->content)->__debugInfo();

        $this->assertArrayHasKey('key', $info);
        $this->assertSame(str_repeat('*', 20), $info['key']);
        $this->assertStringNotContainsString($this->content, $info['key']);
    }

    public function testDebugInfoMasksPath(): void
    {
        $info = Key::fromPath($this->tempPath)->__debugInfo();

        $this->assertArrayHasKey('path', $info);
        $this->assertStringStartsWith('***/', $info['path']);
        $this->assertStringNotContainsString(sys_get_temp_dir(), $info['path']);
    }
}
