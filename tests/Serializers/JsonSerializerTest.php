<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Silencenjoyer\Jwe\JweToken;
use Silencenjoyer\Jwe\Serializers\JsonSerializer;

class JsonSerializerTest extends TestCase
{
    private JsonSerializer $serializer;
    private JweToken       $token;

    protected function setUp(): void
    {
        parent::setUp();

        $this->serializer = new JsonSerializer();
        $this->token      = new JweToken('header', 'enckey', 'iv', 'ciphertext', 'tag');
    }

    public function testSerializeReturnsValidJson(): void
    {
        $this->assertJson($this->serializer->serialize($this->token));
    }

    public function testSerializeOutputHasAllRequiredKeys(): void
    {
        $decoded = json_decode($this->serializer->serialize($this->token), true);

        $this->assertArrayHasKey('protected', $decoded);
        $this->assertArrayHasKey('encrypted_key', $decoded);
        $this->assertArrayHasKey('iv', $decoded);
        $this->assertArrayHasKey('ciphertext', $decoded);
        $this->assertArrayHasKey('tag', $decoded);
    }

    public function testSerializeFieldValues(): void
    {
        $decoded = json_decode($this->serializer->serialize($this->token), true);

        $this->assertSame('header', $decoded['protected']);
        $this->assertSame('enckey', $decoded['encrypted_key']);
        $this->assertSame('iv', $decoded['iv']);
        $this->assertSame('ciphertext', $decoded['ciphertext']);
        $this->assertSame('tag', $decoded['tag']);
    }

    public function testUnserializeValidJsonReturnsJweToken(): void
    {
        $json   = json_encode(['protected' => 'h', 'encrypted_key' => 'e', 'iv' => 'i', 'ciphertext' => 'c', 'tag' => 't']);
        $result = $this->serializer->unserialize($json);

        $this->assertInstanceOf(JweToken::class, $result);
    }

    public function testUnserializeMapsFieldsCorrectly(): void
    {
        $json   = json_encode(['protected' => 'h', 'encrypted_key' => 'e', 'iv' => 'i', 'ciphertext' => 'c', 'tag' => 't']);
        $result = $this->serializer->unserialize($json);

        $this->assertSame('h', $result->protectedHeader);
        $this->assertSame('e', $result->encryptedKey);
        $this->assertSame('i', $result->iv);
        $this->assertSame('c', $result->ciphertext);
        $this->assertSame('t', $result->tag);
    }

    public function testUnserializeBadJsonThrowsInvalidArgumentException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->serializer->unserialize('not-json{{{');
    }

    public function testUnserializeMissingProtectedFieldThrowsInvalidArgumentException(): void
    {
        $json = json_encode(['encrypted_key' => 'e', 'iv' => 'i', 'ciphertext' => 'c', 'tag' => 't']);

        $this->expectException(InvalidArgumentException::class);
        $this->serializer->unserialize($json);
    }

    public function testUnserializeMissingTagFieldThrowsInvalidArgumentException(): void
    {
        $json = json_encode(['protected' => 'h', 'encrypted_key' => 'e', 'iv' => 'i', 'ciphertext' => 'c']);

        $this->expectException(InvalidArgumentException::class);
        $this->serializer->unserialize($json);
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
}
