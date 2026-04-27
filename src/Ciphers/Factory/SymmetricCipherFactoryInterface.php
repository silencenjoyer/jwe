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

use Silencenjoyer\Jwe\Ciphers\SymmetricCipherInterface;
use Silencenjoyer\Jwe\Keys\Key;

interface SymmetricCipherFactoryInterface
{
    public function create(Key $key): SymmetricCipherInterface;

    public function getCekSize(): int;

    public function getAlgorithm(): string;
}
