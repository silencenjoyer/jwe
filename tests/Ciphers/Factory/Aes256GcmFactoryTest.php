<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Ciphers\Aes256Gcm;
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256GcmFactory;
use Silencenjoyer\Jwe\Keys\Key;

class Aes256GcmFactoryTest extends TestCase
{
    private Aes256GcmFactory $factory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->factory = new Aes256GcmFactory();
    }

    public function testGetCekSizeReturns32(): void
    {
        $this->assertSame(32, $this->factory->getCekSize());
    }

    public function testGetAlgorithmReturnsA256Gcm(): void
    {
        $this->assertSame('A256GCM', $this->factory->getAlgorithm());
    }

    public function testCreateReturnsAes256GcmInstance(): void
    {
        $cipher = $this->factory->create(Key::fromContent(str_repeat('k', 32)));
        $this->assertInstanceOf(Aes256Gcm::class, $cipher);
    }
}
