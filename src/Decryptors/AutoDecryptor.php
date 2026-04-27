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
use Silencenjoyer\Jwe\Exceptions\UnsupportedAlgorithmException;
use Silencenjoyer\Jwe\JweHeader;
use Silencenjoyer\Jwe\JweToken;
use Silencenjoyer\Jwe\KeyEncapsulation\KeyUnwrapperInterface;
use Silencenjoyer\Jwe\Keys\Key;

class AutoDecryptor implements DecryptorInterface
{
    /** @var array<string, KeyUnwrapperInterface> */
    private array $unwrappers = [];

    /** @var array<string, SymmetricCipherFactoryInterface> */
    private array $cipherFactories = [];

    public function addUnwrapper(KeyUnwrapperInterface $unwrapper): self
    {
        $this->unwrappers[$unwrapper->getAlgorithm()] = $unwrapper;

        return $this;
    }

    public function addCipherFactory(SymmetricCipherFactoryInterface $factory): self
    {
        $this->cipherFactories[$factory->getAlgorithm()] = $factory;

        return $this;
    }

    public function decrypt(JweToken $token): string
    {
        $header = JweHeader::fromEncoded($token->protectedHeader);
        $alg    = $header->getAlg();
        $enc    = $header->getEnc();

        if (!isset($this->unwrappers[$alg])) {
            throw new UnsupportedAlgorithmException($alg);
        }

        if (!isset($this->cipherFactories[$enc])) {
            throw new UnsupportedAlgorithmException($enc);
        }

        $cek    = $this->unwrappers[$alg]->unwrap($token->encryptedKey);
        $cipher = $this->cipherFactories[$enc]->create(Key::fromContent($cek));

        return $cipher->decrypt(
            new CipherPayload($token->iv, $token->ciphertext, $token->tag),
            $token->protectedHeader,
        );
    }
}
