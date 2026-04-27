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
use Silencenjoyer\Jwe\JweToken;

class JsonSerializer implements SerializerInterface
{
    private const REQUIRED_FIELDS = ['protected', 'encrypted_key', 'iv', 'ciphertext', 'tag'];

    public function serialize(JweToken $token): string
    {
        return json_encode([
            'protected'     => $token->protectedHeader,
            'encrypted_key' => $token->encryptedKey,
            'iv'            => $token->iv,
            'ciphertext'    => $token->ciphertext,
            'tag'           => $token->tag,
        ]);
    }

    public function unserialize(string $data): JweToken
    {
        $decoded = json_decode($data, true);

        if (!is_array($decoded)) {
            throw new InvalidArgumentException('Invalid JWE JSON serialization: malformed JSON.');
        }

        $missing = array_diff(self::REQUIRED_FIELDS, array_keys($decoded));

        if (!empty($missing)) {
            throw new InvalidArgumentException(
                'Invalid JWE JSON serialization: missing fields: ' . implode(', ', $missing) . '.'
            );
        }

        return new JweToken(
            $decoded['protected'],
            $decoded['encrypted_key'],
            $decoded['iv'],
            $decoded['ciphertext'],
            $decoded['tag'],
        );
    }
}
