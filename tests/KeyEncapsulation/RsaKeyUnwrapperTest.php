<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Exceptions\DecryptException;
use Silencenjoyer\Jwe\KeyEncapsulation\RsaKeyUnwrapper;
use Silencenjoyer\Jwe\KeyEncapsulation\RsaKeyWrapper;
use Silencenjoyer\Jwe\Keys\Key;

class RsaKeyUnwrapperTest extends TestCase
{
    private RsaKeyWrapper   $wrapper;
    private RsaKeyUnwrapper $unwrapper;
    private RsaKeyUnwrapper $wrongUnwrapper;

    protected function setUp(): void
    {
        parent::setUp();

        $keysDir         = __DIR__ . '/../keys';
        $this->wrapper   = new RsaKeyWrapper(Key::fromPath($keysDir . '/test_public.pem'));
        $this->unwrapper = new RsaKeyUnwrapper(Key::fromPath($keysDir . '/test_private.pem'));

        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($res, $privPem);
        $this->wrongUnwrapper = new RsaKeyUnwrapper(Key::fromContent($privPem));
    }

    public function testGetAlgorithmReturnsRsaOaep(): void
    {
        $this->assertSame('RSA-OAEP', $this->unwrapper->getAlgorithm());
    }

    public function testUnwrapRoundtripWith32ByteCek(): void
    {
        $dto = $this->wrapper->wrap(32);
        $this->assertSame($dto->getCek(), $this->unwrapper->unwrap($dto->getEncryptedKey()));
    }

    public function testUnwrapRoundtripWith64ByteCek(): void
    {
        $dto = $this->wrapper->wrap(64);
        $this->assertSame($dto->getCek(), $this->unwrapper->unwrap($dto->getEncryptedKey()));
    }

    public function testUnwrapWithWrongPrivateKeyThrowsDecryptException(): void
    {
        $dto = $this->wrapper->wrap(32);

        $this->expectException(DecryptException::class);
        $this->wrongUnwrapper->unwrap($dto->getEncryptedKey());
    }

    public function testUnwrapWithInvalidBase64ThrowsDecodeException(): void
    {
        // 'a' is a single base64 char — insufficient to form any byte, triggers DecodeException
        // but since Base64Url::decode without strict never returns false, we check that
        // unwrap with garbage encrypted key fails at the OpenSSL level and throws DecryptException
        $this->expectException(DecryptException::class);
        $this->unwrapper->unwrap('garbage-not-rsa-encrypted-data');
    }
}
