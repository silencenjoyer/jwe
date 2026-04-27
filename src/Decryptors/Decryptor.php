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

namespace Silencenjoyer\Jwe\Decryptors;

use Silencenjoyer\Jwe\Ciphers\CipherPayload;
use Silencenjoyer\Jwe\Ciphers\Factory\SymmetricCipherFactoryInterface;
use Silencenjoyer\Jwe\JweToken;
use Silencenjoyer\Jwe\KeyEncapsulation\KeyUnwrapperInterface;
use Silencenjoyer\Jwe\Keys\Key;

class Decryptor implements DecryptorInterface
{
    private KeyUnwrapperInterface $keyUnwrapper;
    private SymmetricCipherFactoryInterface $cipherFactory;

    public function __construct(KeyUnwrapperInterface $keyUnwrapper, SymmetricCipherFactoryInterface $cipherFactory)
    {
        $this->keyUnwrapper  = $keyUnwrapper;
        $this->cipherFactory = $cipherFactory;
    }

    public function decrypt(JweToken $token): string
    {
        $cek    = $this->keyUnwrapper->unwrap($token->encryptedKey);
        $cipher = $this->cipherFactory->create(Key::fromContent($cek));

        return $cipher->decrypt(
            new CipherPayload($token->iv, $token->ciphertext, $token->tag),
            $token->protectedHeader,
        );
    }
}
