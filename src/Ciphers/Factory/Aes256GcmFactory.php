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

use Silencenjoyer\Jwe\Ciphers\Aes256Gcm;
use Silencenjoyer\Jwe\Ciphers\SymmetricCipherInterface;
use Silencenjoyer\Jwe\Keys\Key;

class Aes256GcmFactory implements SymmetricCipherFactoryInterface
{
    private const CEK_LEN = 32;
    private const ALGO = 'A256GCM';

    public function create(Key $key): SymmetricCipherInterface
    {
        return new Aes256Gcm($key);
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
