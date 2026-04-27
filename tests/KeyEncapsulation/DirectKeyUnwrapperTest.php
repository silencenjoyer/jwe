<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyUnwrapper;
use Silencenjoyer\Jwe\Keys\Key;

class DirectKeyUnwrapperTest extends TestCase
{
    private string           $keyContent;
    private DirectKeyUnwrapper $unwrapper;

    protected function setUp(): void
    {
        parent::setUp();

        $this->keyContent = str_repeat('d', 32);
        $this->unwrapper  = new DirectKeyUnwrapper(Key::fromContent($this->keyContent));
    }

    public function testGetAlgorithmReturnsDir(): void
    {
        $this->assertSame('dir', $this->unwrapper->getAlgorithm());
    }

    public function testUnwrapReturnsSharedKeyContent(): void
    {
        $this->assertSame($this->keyContent, $this->unwrapper->unwrap(''));
    }

    public function testUnwrapIgnoresWrappedArgument(): void
    {
        $this->assertSame($this->keyContent, $this->unwrapper->unwrap('ignored-garbage'));
    }
}
