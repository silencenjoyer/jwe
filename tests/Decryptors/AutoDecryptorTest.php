<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256CbcFactory;
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256GcmFactory;
use Silencenjoyer\Jwe\Decryptors\AutoDecryptor;
use Silencenjoyer\Jwe\Encryptors\Encryptor;
use Silencenjoyer\Jwe\Exceptions\DecodeException;
use Silencenjoyer\Jwe\Exceptions\UnsupportedAlgorithmException;
use Silencenjoyer\Jwe\JweToken;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyUnwrapper;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyWrapper;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Util\Base64Url;

class AutoDecryptorTest extends TestCase
{
    private Key $sharedKey32;
    private Key $sharedKey64;

    protected function setUp(): void
    {
        parent::setUp();

        $this->sharedKey32 = Key::fromContent(str_repeat('k', 32));
        $this->sharedKey64 = Key::fromContent(str_repeat('k', 64));
    }

    public function testRoundtripDirAes256Gcm(): void
    {
        $plain = 'Hello, JWE!';

        $encryptor = new Encryptor(
            new DirectKeyWrapper($this->sharedKey32),
            new Aes256GcmFactory(),
        );

        $decryptor = (new AutoDecryptor())
            ->addUnwrapper(new DirectKeyUnwrapper($this->sharedKey32))
            ->addCipherFactory(new Aes256GcmFactory());

        $this->assertSame($plain, $decryptor->decrypt($encryptor->encrypt($plain)));
    }

    public function testRoundtripDirAes256Cbc(): void
    {
        $plain = 'Привет, мир!';

        $encryptor = new Encryptor(
            new DirectKeyWrapper($this->sharedKey64),
            new Aes256CbcFactory(),
        );

        $decryptor = (new AutoDecryptor())
            ->addUnwrapper(new DirectKeyUnwrapper($this->sharedKey64))
            ->addCipherFactory(new Aes256CbcFactory());

        $this->assertSame($plain, $decryptor->decrypt($encryptor->encrypt($plain)));
    }

    public function testUnknownAlgThrowsUnsupportedAlgorithmException(): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);

        $header = Base64Url::encode(json_encode(['alg' => 'UNKNOWN', 'enc' => 'A256GCM']));
        $token  = new JweToken($header, '', '', '', '');

        $decryptor = (new AutoDecryptor())->addCipherFactory(new Aes256GcmFactory());
        $decryptor->decrypt($token);
    }

    public function testUnknownEncThrowsUnsupportedAlgorithmException(): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);

        $header = Base64Url::encode(json_encode(['alg' => 'dir', 'enc' => 'UNKNOWN']));
        $token  = new JweToken($header, '', '', '', '');

        $decryptor = (new AutoDecryptor())->addUnwrapper(new DirectKeyUnwrapper($this->sharedKey32));
        $decryptor->decrypt($token);
    }

    public function testInvalidProtectedHeaderThrowsDecodeException(): void
    {
        $this->expectException(DecodeException::class);

        $token     = new JweToken('not-valid-base64!!!', '', '', '', '');
        $decryptor = new AutoDecryptor();
        $decryptor->decrypt($token);
    }
}
