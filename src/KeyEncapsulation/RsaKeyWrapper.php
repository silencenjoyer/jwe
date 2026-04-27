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

namespace Silencenjoyer\Jwe\KeyEncapsulation;

use Silencenjoyer\Jwe\Exceptions\InvalidKeyException;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Util\Base64Url;

class RsaKeyWrapper implements KeyWrapperInterface
{
    private Key $publicKey;

    public function __construct(Key $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function getAlgorithm(): string
    {
        return 'RSA-OAEP';
    }

    public function wrap(int $cekSize): WrappedKeyDto
    {
        $cek    = random_bytes($cekSize);
        $result = openssl_public_encrypt($cek, $encryptedKey, $this->publicKey->asContent(), OPENSSL_PKCS1_OAEP_PADDING);

        if ($result === false) {
            throw new InvalidKeyException();
        }

        return new WrappedKeyDto($cek, Base64Url::encode($encryptedKey));
    }
}
