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
use Silencenjoyer\Jwe\Exceptions\EncryptIntegrityViolation;
use Silencenjoyer\Jwe\Exceptions\InvalidKeyException;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Mac\HmacMac;
use Silencenjoyer\Jwe\Util\Base64Url;

class Aes256Cbc implements SymmetricCipherInterface
{
    private const CIPHER = 'aes-256-cbc';

    private Key     $key;
    private HmacMac $mac;

    public function __construct(Key $key, HmacMac $mac)
    {
        if (strlen($key->asContent()) !== 32) {
            throw new InvalidKeyException('Key must be 32 bytes');
        }

        $this->key = $key;
        $this->mac = $mac;
    }

    public function encrypt(string $plainData, string $aad): CipherPayload
    {
        $iv = random_bytes(16);

        $ciphertext = openssl_encrypt($plainData, self::CIPHER, $this->key->asContent(), OPENSSL_RAW_DATA, $iv);

        if ($ciphertext === false) {
            throw new EncryptException();
        }

        return new CipherPayload(
            Base64Url::encode($iv),
            Base64Url::encode($ciphertext),
            Base64Url::encode($this->mac->sign($aad, $iv, $ciphertext)),
        );
    }

    public function decrypt(CipherPayload $payload, string $aad): string
    {
        $iv         = Base64Url::decode($payload->iv);
        $ciphertext = Base64Url::decode($payload->ciphertext);
        $tag        = Base64Url::decode($payload->tag);

        if (!$this->mac->verify($aad, $iv, $ciphertext, $tag)) {
            throw new EncryptIntegrityViolation();
        }

        $plaintext = openssl_decrypt($ciphertext, self::CIPHER, $this->key->asContent(), OPENSSL_RAW_DATA, $iv);

        if ($plaintext === false) {
            throw new DecryptException();
        }

        return $plaintext;
    }
}
