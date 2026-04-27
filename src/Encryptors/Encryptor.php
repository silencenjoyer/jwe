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

namespace Silencenjoyer\Jwe\Encryptors;

use Silencenjoyer\Jwe\Ciphers\Factory\SymmetricCipherFactoryInterface;
use Silencenjoyer\Jwe\JweHeader;
use Silencenjoyer\Jwe\JweToken;
use Silencenjoyer\Jwe\KeyEncapsulation\KeyWrapperInterface;
use Silencenjoyer\Jwe\Keys\Key;

/**
 * JWE JSON Serialization encryptor (RFC 7516).
 *
 * Output fields: protected, encrypted_key, iv, ciphertext, tag.
 * The protected header (base64url-encoded JSON) is used as AAD for the content
 * cipher, cryptographically binding all JWE fields together.
 */
class Encryptor implements EncryptorInterface
{
    private KeyWrapperInterface             $keyWrapper;
    private SymmetricCipherFactoryInterface $cipherFactory;

    public function __construct(KeyWrapperInterface $keyWrapper, SymmetricCipherFactoryInterface $cipherFactory)
    {
        $this->keyWrapper    = $keyWrapper;
        $this->cipherFactory = $cipherFactory;
    }

    public function encrypt(string $plainData): JweToken
    {
        $header          = new JweHeader($this->keyWrapper->getAlgorithm(), $this->cipherFactory->getAlgorithm());
        $protectedHeader = $header->encode();

        $wrappedKey = $this->keyWrapper->wrap($this->cipherFactory->getCekSize());

        $cipher  = $this->cipherFactory->create(Key::fromContent($wrappedKey->getCek()));
        $payload = $cipher->encrypt($plainData, $protectedHeader);

        return new JweToken(
            $protectedHeader,
            $wrappedKey->getEncryptedKey(),
            $payload->iv,
            $payload->ciphertext,
            $payload->tag,
        );
    }
}
