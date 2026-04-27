<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\Exceptions\DeserializeException;
use Silencenjoyer\Jwe\JweToken;
use Silencenjoyer\Jwe\Serializers\CompactSerializer;

class CompactSerializerTest extends TestCase
{
    private CompactSerializer $serializer;
    private JweToken          $token;

    protected function setUp(): void
    {
        parent::setUp();

        $this->serializer = new CompactSerializer();
        $this->token      = new JweToken('header', 'enckey', 'iv', 'ciphertext', 'tag');
    }

    public function testSerializeProducesFiveDotDelimitedParts(): void
    {
        $compact = $this->serializer->serialize($this->token);
        $this->assertSame(4, substr_count($compact, '.'));
    }

    public function testSerializeFieldOrder(): void
    {
        $parts = explode('.', $this->serializer->serialize($this->token));

        $this->assertSame('header', $parts[0]);
        $this->assertSame('enckey', $parts[1]);
        $this->assertSame('iv', $parts[2]);
        $this->assertSame('ciphertext', $parts[3]);
        $this->assertSame('tag', $parts[4]);
    }

    public function testUnserializeValidTokenReturnsJweToken(): void
    {
        $result = $this->serializer->unserialize('header.enckey.iv.ciphertext.tag');

        $this->assertInstanceOf(JweToken::class, $result);
        $this->assertSame('header', $result->protectedHeader);
        $this->assertSame('enckey', $result->encryptedKey);
        $this->assertSame('iv', $result->iv);
        $this->assertSame('ciphertext', $result->ciphertext);
        $this->assertSame('tag', $result->tag);
    }

    public function testUnserializeWithTooFewPartsThrowsDeserializeException(): void
    {
        $this->expectException(DeserializeException::class);
        $this->serializer->unserialize('only.four.parts.here');
    }

    public function testUnserializeWithTooManyPartsThrowsDeserializeException(): void
    {
        $this->expectException(DeserializeException::class);
        $this->serializer->unserialize('a.b.c.d.e.f');
    }

    public function testRoundtrip(): void
    {
        $recovered = $this->serializer->unserialize($this->serializer->serialize($this->token));

        $this->assertSame($this->token->protectedHeader, $recovered->protectedHeader);
        $this->assertSame($this->token->encryptedKey, $recovered->encryptedKey);
        $this->assertSame($this->token->iv, $recovered->iv);
        $this->assertSame($this->token->ciphertext, $recovered->ciphertext);
        $this->assertSame($this->token->tag, $recovered->tag);
    }

    public function testSerializeWithEmptyEncryptedKeyProducesDoubleDot(): void
    {
        $token   = new JweToken('header', '', 'iv', 'ciphertext', 'tag');
        $compact = $this->serializer->serialize($token);

        $this->assertStringContainsString('header..iv', $compact);
    }
}
