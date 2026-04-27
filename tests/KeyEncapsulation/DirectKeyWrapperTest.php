<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyWrapper;
use Silencenjoyer\Jwe\Keys\Key;

class DirectKeyWrapperTest extends TestCase
{
    private string         $keyContent;
    private DirectKeyWrapper $wrapper;

    protected function setUp(): void
    {
        parent::setUp();

        $this->keyContent = str_repeat('d', 32);
        $this->wrapper    = new DirectKeyWrapper(Key::fromContent($this->keyContent));
    }

    public function testGetAlgorithmReturnsDir(): void
    {
        $this->assertSame('dir', $this->wrapper->getAlgorithm());
    }

    public function testWrapGetCekEqualsSharedKeyContent(): void
    {
        $this->assertSame($this->keyContent, $this->wrapper->wrap(32)->getCek());
    }

    public function testWrapGetEncryptedKeyIsEmptyString(): void
    {
        $this->assertSame('', $this->wrapper->wrap(32)->getEncryptedKey());
    }

    public function testWrapIgnoresCekSizeParameter(): void
    {
        $this->assertSame($this->keyContent, $this->wrapper->wrap(999)->getCek());
    }
}
