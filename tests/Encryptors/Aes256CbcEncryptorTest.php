<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Ciphers\Aes256Cbc;
use Silencenjoyer\Jwe\Ciphers\CipherPayload;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Mac\HmacMac;

class Aes256CbcEncryptorTest extends TestCase
{
    private Aes256Cbc $cipher;
    private string $aad = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ';

    protected function setUp(): void
    {
        parent::setUp();

        $this->cipher = new Aes256Cbc(
            Key::fromContent(str_repeat('a', 32)),
            new HmacMac(str_repeat('b', 32), 'sha512', 32),
        );
    }

    public function testEncryptReturnsExpectedFields(): void
    {
        $encrypted = $this->cipher->encrypt('Hello World!', $this->aad);

        $this->assertInstanceOf(CipherPayload::class, $encrypted);
        $this->assertNotEmpty($encrypted->iv);
        $this->assertNotEmpty($encrypted->ciphertext);
        $this->assertNotEmpty($encrypted->tag);
    }

    public function testEncryptProducesDifferentCiphertextsEachTime(): void
    {
        $first  = $this->cipher->encrypt('Hello World!', $this->aad);
        $second = $this->cipher->encrypt('Hello World!', $this->aad);

        $this->assertNotEquals($first->ciphertext, $second->ciphertext);
    }

    public function testDecryptRoundtrip(): void
    {
        $plain     = 'Привет, мир!';
        $encrypted = $this->cipher->encrypt($plain, $this->aad);

        $this->assertSame($plain, $this->cipher->decrypt($encrypted, $this->aad));
    }
}