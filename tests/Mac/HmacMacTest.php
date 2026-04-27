<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Mac\HmacMac;

class HmacMacTest extends TestCase
{
    private HmacMac $mac;
    private string  $aad;
    private string  $iv;
    private string  $ciphertext;

    protected function setUp(): void
    {
        parent::setUp();

        $this->mac        = new HmacMac(str_repeat('k', 32), 'sha512', 32);
        $this->aad        = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0';
        $this->iv         = str_repeat("\x01", 16);
        $this->ciphertext = 'someciphertextbytes';
    }

    public function testSignReturnsStringOfExpectedLength(): void
    {
        $tag = $this->mac->sign($this->aad, $this->iv, $this->ciphertext);
        $this->assertSame(32, strlen($tag));
    }

    public function testSignProducesKnownVector(): void
    {
        $al      = pack('N2', 0, strlen($this->aad) * 8);
        $message = $this->aad . $this->iv . $this->ciphertext . $al;
        $full    = hash_hmac('sha512', $message, str_repeat('k', 32), true);
        $expected = substr($full, 0, 32);

        $this->assertSame($expected, $this->mac->sign($this->aad, $this->iv, $this->ciphertext));
    }

    public function testVerifyReturnsTrueForCorrectTag(): void
    {
        $tag = $this->mac->sign($this->aad, $this->iv, $this->ciphertext);
        $this->assertTrue($this->mac->verify($this->aad, $this->iv, $this->ciphertext, $tag));
    }

    public function testVerifyReturnsFalseForTamperedCiphertext(): void
    {
        $tag = $this->mac->sign($this->aad, $this->iv, $this->ciphertext);
        $this->assertFalse($this->mac->verify($this->aad, $this->iv, 'tampered!', $tag));
    }

    public function testVerifyReturnsFalseForTamperedTag(): void
    {
        $tag    = $this->mac->sign($this->aad, $this->iv, $this->ciphertext);
        $badTag = $tag;
        $badTag[0] = chr(ord($badTag[0]) ^ 0xFF);

        $this->assertFalse($this->mac->verify($this->aad, $this->iv, $this->ciphertext, $badTag));
    }

    public function testVerifyReturnsFalseForWrongKey(): void
    {
        $tag      = $this->mac->sign($this->aad, $this->iv, $this->ciphertext);
        $wrongMac = new HmacMac(str_repeat('z', 32), 'sha512', 32);

        $this->assertFalse($wrongMac->verify($this->aad, $this->iv, $this->ciphertext, $tag));
    }
}
