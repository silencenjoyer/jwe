<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Ciphers\Aes256Gcm;
use Silencenjoyer\Jwe\Ciphers\CipherPayload;
use Silencenjoyer\Jwe\Exceptions\DecryptException;
use Silencenjoyer\Jwe\Exceptions\InvalidKeyException;
use Silencenjoyer\Jwe\Keys\Key;

class Aes256GcmTest extends TestCase
{
    private Aes256Gcm $cipher;
    private string    $aad;

    protected function setUp(): void
    {
        parent::setUp();

        $this->cipher = new Aes256Gcm(Key::fromContent(str_repeat('g', 32)));
        $this->aad    = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0';
    }

    public function testConstructorThrowsInvalidKeyExceptionForShortKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        new Aes256Gcm(Key::fromContent(str_repeat('x', 16)));
    }

    public function testConstructorThrowsInvalidKeyExceptionForLongKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        new Aes256Gcm(Key::fromContent(str_repeat('x', 64)));
    }

    public function testEncryptReturnsInstanceOfCipherPayload(): void
    {
        $this->assertInstanceOf(CipherPayload::class, $this->cipher->encrypt('plaintext', $this->aad));
    }

    public function testEncryptReturnsNonEmptyIv(): void
    {
        $this->assertNotEmpty($this->cipher->encrypt('plaintext', $this->aad)->iv);
    }

    public function testEncryptIvIsRandomized(): void
    {
        $first  = $this->cipher->encrypt('same plaintext', $this->aad);
        $second = $this->cipher->encrypt('same plaintext', $this->aad);

        $this->assertNotEquals($first->iv, $second->iv);
    }

    public function testDecryptRoundtrip(): void
    {
        $plain   = 'Hello, GCM!';
        $payload = $this->cipher->encrypt($plain, $this->aad);

        $this->assertSame($plain, $this->cipher->decrypt($payload, $this->aad));
    }

    public function testDecryptWithWrongAadThrowsDecryptException(): void
    {
        $payload = $this->cipher->encrypt('secret', $this->aad);

        $this->expectException(DecryptException::class);
        $this->cipher->decrypt($payload, 'wrong-aad');
    }

    public function testDecryptWithWrongKeyThrowsDecryptException(): void
    {
        $payload     = $this->cipher->encrypt('secret', $this->aad);
        $wrongCipher = new Aes256Gcm(Key::fromContent(str_repeat('z', 32)));

        $this->expectException(DecryptException::class);
        $wrongCipher->decrypt($payload, $this->aad);
    }
}
