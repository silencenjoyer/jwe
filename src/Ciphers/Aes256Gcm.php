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

namespace Silencenjoyer\Jwe\Ciphers;

use Silencenjoyer\Jwe\Exceptions\DecryptException;
use Silencenjoyer\Jwe\Exceptions\EncryptException;
use Silencenjoyer\Jwe\Exceptions\InvalidKeyException;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Util\Base64Url;

/**
 * AES-256-GCM content encryption (RFC 7518 §5.3, "A256GCM").
 *
 * CEK must be 32 bytes. The protected header is passed as AAD and is
 * authenticated by the GCM tag, binding the ciphertext to all JWE fields.
 */
class Aes256Gcm implements SymmetricCipherInterface
{
    private const CIPHER = 'aes-256-gcm';

    private Key $key;

    public function __construct(Key $key)
    {
        if (strlen($key->asContent()) !== 32) {
            throw new InvalidKeyException('Key must be 32 bytes');
        }

        $this->key = $key;
    }

    public function encrypt(string $plainData, string $aad): CipherPayload
    {
        $iv  = random_bytes(12);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plainData,
            self::CIPHER,
            $this->key->asContent(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );

        if ($ciphertext === false) {
            throw new EncryptException('Encryption failed');
        }

        return new CipherPayload(
            Base64Url::encode($iv),
            Base64Url::encode($ciphertext),
            Base64Url::encode($tag),
        );
    }

    public function decrypt(CipherPayload $payload, string $aad): string
    {
        $iv         = Base64Url::decode($payload->iv);
        $ciphertext = Base64Url::decode($payload->ciphertext);
        $tag        = Base64Url::decode($payload->tag);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->key->asContent(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );

        if ($plaintext === false) {
            throw new DecryptException();
        }

        return $plaintext;
    }
}
