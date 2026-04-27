<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256CbcFactory;
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256GcmFactory;
use Silencenjoyer\Jwe\Encryptors\Encryptor;
use Silencenjoyer\Jwe\JweHeader;
use Silencenjoyer\Jwe\JweToken;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyWrapper;
use Silencenjoyer\Jwe\KeyEncapsulation\RsaKeyWrapper;
use Silencenjoyer\Jwe\Keys\Key;

class EncryptorTest extends TestCase
{
    private Encryptor $encryptorDirGcm;
    private Encryptor $encryptorDirCbc;
    private Encryptor $encryptorRsaGcm;

    protected function setUp(): void
    {
        parent::setUp();

        $keysDir = __DIR__ . '/../keys';

        $this->encryptorDirGcm = new Encryptor(
            new DirectKeyWrapper(Key::fromContent(str_repeat('e', 32))),
            new Aes256GcmFactory(),
        );
        $this->encryptorDirCbc = new Encryptor(
            new DirectKeyWrapper(Key::fromContent(str_repeat('e', 64))),
            new Aes256CbcFactory(),
        );
        $this->encryptorRsaGcm = new Encryptor(
            new RsaKeyWrapper(Key::fromPath($keysDir . '/test_public.pem')),
            new Aes256GcmFactory(),
        );
    }

    public function testEncryptReturnsJweTokenInstance(): void
    {
        $this->assertInstanceOf(JweToken::class, $this->encryptorDirGcm->encrypt('hello'));
    }

    public function testEncryptProtectedHeaderIsNonEmpty(): void
    {
        $this->assertNotEmpty($this->encryptorDirGcm->encrypt('hello')->protectedHeader);
    }

    public function testEncryptCiphertextIsNonEmpty(): void
    {
        $this->assertNotEmpty($this->encryptorDirGcm->encrypt('hello')->ciphertext);
    }

    public function testEncryptDirAlgorithmInHeader(): void
    {
        $token  = $this->encryptorDirGcm->encrypt('hello');
        $header = JweHeader::fromEncoded($token->protectedHeader);

        $this->assertSame('dir', $header->getAlg());
        $this->assertSame('A256GCM', $header->getEnc());
    }

    public function testEncryptDirCbcAlgorithmInHeader(): void
    {
        $header = JweHeader::fromEncoded($this->encryptorDirCbc->encrypt('hello')->protectedHeader);

        $this->assertSame('dir', $header->getAlg());
        $this->assertSame('A256CBC-HS512', $header->getEnc());
    }

    public function testEncryptRsaGcmAlgorithmInHeader(): void
    {
        $header = JweHeader::fromEncoded($this->encryptorRsaGcm->encrypt('hello')->protectedHeader);

        $this->assertSame('RSA-OAEP', $header->getAlg());
        $this->assertSame('A256GCM', $header->getEnc());
    }

    public function testEncryptDirGcmEncryptedKeyIsEmpty(): void
    {
        $this->assertSame('', $this->encryptorDirGcm->encrypt('hello')->encryptedKey);
    }

    public function testEncryptRsaGcmEncryptedKeyIsNonEmpty(): void
    {
        $this->assertNotEmpty($this->encryptorRsaGcm->encrypt('hello')->encryptedKey);
    }
}
