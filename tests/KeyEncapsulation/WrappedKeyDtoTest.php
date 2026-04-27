<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\KeyEncapsulation\WrappedKeyDto;

class WrappedKeyDtoTest extends TestCase
{
    public function testGetCekReturnsConstructedValue(): void
    {
        $dto = new WrappedKeyDto('the-cek', 'enc-key');
        $this->assertSame('the-cek', $dto->getCek());
    }

    public function testGetEncryptedKeyReturnsConstructedValue(): void
    {
        $dto = new WrappedKeyDto('the-cek', 'enc-key');
        $this->assertSame('enc-key', $dto->getEncryptedKey());
    }

    public function testBothFieldsCanBeEmptyString(): void
    {
        $dto = new WrappedKeyDto('', '');
        $this->assertSame('', $dto->getCek());
        $this->assertSame('', $dto->getEncryptedKey());
    }
}
