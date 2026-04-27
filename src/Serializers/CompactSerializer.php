<?php

/*
 * This file is part of the Encryptor package.
 *
 * (c) Andrew Gebrich <an_gebrich@outlook.com>
 *
 * For the full copyright and license information, please view the LICENSE file that was distributed with this
 * source code.
 */

declare(strict_types=1);

namespace Silencenjoyer\Jwe\Serializers;

use InvalidArgumentException;
use Silencenjoyer\Jwe\Exceptions\DeserializeException;
use Silencenjoyer\Jwe\JweToken;

/**
 * JWE Compact Serialization (RFC 7516 §7.1).
 *
 * Format: BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)
 * All five components are dot-delimited. For "dir" key agreement, encrypted_key is the empty string.
 */
class CompactSerializer implements SerializerInterface
{
    public function serialize(JweToken $token): string
    {
        return implode('.', [
            $token->protectedHeader,
            $token->encryptedKey,
            $token->iv,
            $token->ciphertext,
            $token->tag,
        ]);
    }

    public function unserialize(string $data): JweToken
    {
        $parts = explode('.', $data);

        if (count($parts) !== 5) {
            throw new DeserializeException('Invalid JWE compact serialization: expected 5 parts.');
        }

        [$protectedHeader, $encryptedKey, $iv, $ciphertext, $tag] = $parts;

        return new JweToken($protectedHeader, $encryptedKey, $iv, $ciphertext, $tag);
    }
}
