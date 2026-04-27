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

namespace Silencenjoyer\Jwe\Exceptions;

class UnsupportedAlgorithmException extends CipheringException
{
    public function __construct(string $algorithm)
    {
        parent::__construct(sprintf('Unsupported algorithm: "%s".', $algorithm));
    }
}
