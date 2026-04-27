<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256CbcFactory;
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256GcmFactory;
use Silencenjoyer\Jwe\Decryptors\Decryptor;
use Silencenjoyer\Jwe\Encryptors\Encryptor;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyUnwrapper;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyWrapper;
use Silencenjoyer\Jwe\KeyEncapsulation\RsaKeyUnwrapper;
use Silencenjoyer\Jwe\KeyEncapsulation\RsaKeyWrapper;
use Silencenjoyer\Jwe\Keys\Key;

class DecryptorTest extends TestCase
{
    private Key $sharedKey32;
    private Key $sharedKey64;
    private Key $publicKey;
    private Key $privateKey;

    protected function setUp(): void
    {
        parent::setUp();

        $keysDir = __DIR__ . '/../keys';

        $this->sharedKey32 = Key::fromContent(str_repeat('d', 32));
        $this->sharedKey64 = Key::fromContent(str_repeat('d', 64));
        $this->publicKey   = Key::fromPath($keysDir . '/test_public.pem');
        $this->privateKey  = Key::fromPath($keysDir . '/test_private.pem');
    }

    public function testRoundtripDirAes256Gcm(): void
    {
        $plain     = 'Secret message GCM';
        $encryptor = new Encryptor(new DirectKeyWrapper($this->sharedKey32), new Aes256GcmFactory());
        $decryptor = new Decryptor(new DirectKeyUnwrapper($this->sharedKey32), new Aes256GcmFactory());

        $this->assertSame($plain, $decryptor->decrypt($encryptor->encrypt($plain)));
    }

    public function testRoundtripDirAes256Cbc(): void
    {
        $plain     = 'Привет, мир!';
        $encryptor = new Encryptor(new DirectKeyWrapper($this->sharedKey64), new Aes256CbcFactory());
        $decryptor = new Decryptor(new DirectKeyUnwrapper($this->sharedKey64), new Aes256CbcFactory());

        $this->assertSame($plain, $decryptor->decrypt($encryptor->encrypt($plain)));
    }

    public function testRoundtripRsaAes256Gcm(): void
    {
        $plain     = 'RSA+GCM roundtrip';
        $encryptor = new Encryptor(new RsaKeyWrapper($this->publicKey), new Aes256GcmFactory());
        $decryptor = new Decryptor(new RsaKeyUnwrapper($this->privateKey), new Aes256GcmFactory());

        $this->assertSame($plain, $decryptor->decrypt($encryptor->encrypt($plain)));
    }

    public function testRoundtripRsaAes256Cbc(): void
    {
        $plain     = 'RSA+CBC roundtrip';
        $encryptor = new Encryptor(new RsaKeyWrapper($this->publicKey), new Aes256CbcFactory());
        $decryptor = new Decryptor(new RsaKeyUnwrapper($this->privateKey), new Aes256CbcFactory());

        $this->assertSame($plain, $decryptor->decrypt($encryptor->encrypt($plain)));
    }

    public function testDecryptProducesExactOriginalPlaintext(): void
    {
        $plain     = 'The quick brown fox 🦊 jumps over the lazy dog';
        $encryptor = new Encryptor(new DirectKeyWrapper($this->sharedKey32), new Aes256GcmFactory());
        $decryptor = new Decryptor(new DirectKeyUnwrapper($this->sharedKey32), new Aes256GcmFactory());

        $this->assertSame($plain, $decryptor->decrypt($encryptor->encrypt($plain)));
    }
}
