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

use Silencenjoyer\Jwe\Exceptions\DecryptException;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Util\Base64Url;

class RsaKeyUnwrapper implements KeyUnwrapperInterface
{
    private Key $privateKey;

    public function __construct(Key $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    public function getAlgorithm(): string
    {
        return 'RSA-OAEP';
    }

    public function unwrap(string $wrapped): string
    {
        $result = openssl_private_decrypt(
            Base64Url::decode($wrapped),
            $key,
            $this->privateKey->asContent(),
            OPENSSL_PKCS1_OAEP_PADDING
        );

        if ($result === false) {
            throw new DecryptException();
        }

        return $key;
    }
}
