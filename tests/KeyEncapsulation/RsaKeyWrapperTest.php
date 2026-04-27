<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Exceptions\InvalidKeyException;
use Silencenjoyer\Jwe\KeyEncapsulation\RsaKeyWrapper;
use Silencenjoyer\Jwe\Keys\Key;

class RsaKeyWrapperTest extends TestCase
{
    private RsaKeyWrapper $wrapper;

    protected function setUp(): void
    {
        parent::setUp();

        $keysDir       = __DIR__ . '/../keys';
        $this->wrapper = new RsaKeyWrapper(Key::fromPath($keysDir . '/test_public.pem'));
    }

    public function testGetAlgorithmReturnsRsaOaep(): void
    {
        $this->assertSame('RSA-OAEP', $this->wrapper->getAlgorithm());
    }

    public function testWrapReturnsCekOfRequestedSize(): void
    {
        $dto = $this->wrapper->wrap(32);
        $this->assertSame(32, strlen($dto->getCek()));
    }

    public function testWrapGetEncryptedKeyIsNonEmpty(): void
    {
        $this->assertNotEmpty($this->wrapper->wrap(32)->getEncryptedKey());
    }

    public function testWrapCekIsRandomized(): void
    {
        $first  = $this->wrapper->wrap(32);
        $second = $this->wrapper->wrap(32);

        $this->assertNotEquals($first->getCek(), $second->getCek());
    }

    public function testWrapWithInvalidKeyThrowsInvalidKeyException(): void
    {
        $badWrapper = new RsaKeyWrapper(Key::fromContent('not-a-pem-key'));

        $this->expectException(InvalidKeyException::class);

        set_error_handler(static function (): bool { return true; }, E_WARNING);
        try {
            $badWrapper->wrap(32);
        } finally {
            restore_error_handler();
        }
    }
}
