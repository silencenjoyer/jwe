<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Exceptions\DecodeException;
use Silencenjoyer\Jwe\JweHeader;
use Silencenjoyer\Jwe\Util\Base64Url;

class JweHeaderTest extends TestCase
{
    public function testEncodeRoundtrip(): void
    {
        $header  = new JweHeader('RSA-OAEP', 'A256GCM');
        $encoded = $header->encode();
        $decoded = JweHeader::fromEncoded($encoded);

        $this->assertSame('RSA-OAEP', $decoded->getAlg());
        $this->assertSame('A256GCM', $decoded->getEnc());
    }

    public function testEncodeMatchesManualConstruction(): void
    {
        $alg     = 'dir';
        $enc     = 'A256CBC-HS512';
        $header  = new JweHeader($alg, $enc);
        $expected = Base64Url::encode(json_encode(['alg' => $alg, 'enc' => $enc], JSON_UNESCAPED_SLASHES));

        $this->assertSame($expected, $header->encode());
    }

    public function testFromEncodedWithInvalidBase64ThrowsDecodeException(): void
    {
        $this->expectException(DecodeException::class);

        JweHeader::fromEncoded('not valid base64!!!');
    }

    public function testFromEncodedWithMissingAlgThrowsDecodeException(): void
    {
        $this->expectException(DecodeException::class);

        $encoded = Base64Url::encode(json_encode(['enc' => 'A256GCM']));
        JweHeader::fromEncoded($encoded);
    }

    public function testFromEncodedWithMissingEncThrowsDecodeException(): void
    {
        $this->expectException(DecodeException::class);

        $encoded = Base64Url::encode(json_encode(['alg' => 'dir']));
        JweHeader::fromEncoded($encoded);
    }

    public function testFromEncodedWithInvalidJsonThrowsDecodeException(): void
    {
        $this->expectException(DecodeException::class);

        JweHeader::fromEncoded(Base64Url::encode('not-json'));
    }
}
