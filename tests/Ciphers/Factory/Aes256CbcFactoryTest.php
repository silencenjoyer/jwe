<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Ciphers\Aes256Cbc;
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256CbcFactory;
use Silencenjoyer\Jwe\Keys\Key;

class Aes256CbcFactoryTest extends TestCase
{
    private Aes256CbcFactory $factory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->factory = new Aes256CbcFactory();
    }

    public function testGetCekSizeReturns64(): void
    {
        $this->assertSame(64, $this->factory->getCekSize());
    }

    public function testGetAlgorithmReturnsA256CbcHs512(): void
    {
        $this->assertSame('A256CBC-HS512', $this->factory->getAlgorithm());
    }

    public function testCreateReturnsAes256CbcInstance(): void
    {
        $cipher = $this->factory->create(Key::fromContent(str_repeat('k', 64)));
        $this->assertInstanceOf(Aes256Cbc::class, $cipher);
    }
}
