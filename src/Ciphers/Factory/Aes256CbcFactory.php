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

namespace Silencenjoyer\Jwe\Ciphers\Factory;

use Silencenjoyer\Jwe\Ciphers\Aes256Cbc;
use Silencenjoyer\Jwe\Ciphers\SymmetricCipherInterface;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Mac\HmacMac;

class Aes256CbcFactory implements SymmetricCipherFactoryInterface
{
    private const CEK_LEN = 64;
    private const HMAC_ALGO = 'sha512';
    private const ALGO = 'A256CBC-HS512';

    public function create(Key $cek): SymmetricCipherInterface
    {
        $raw = $cek->asContent();

        return new Aes256Cbc(
            Key::fromContent(substr($raw, 32, 32)),
            new HmacMac(substr($raw, 0, 32), self::HMAC_ALGO, 32),
        );
    }

    public function getCekSize(): int
    {
        return self::CEK_LEN;
    }

    public function getAlgorithm(): string
    {
        return self::ALGO;
    }
}
