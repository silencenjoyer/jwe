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

class CipherPayload
{
    public string $iv;
    public string $ciphertext;
    public string $tag;

    public function __construct(string $iv, string $ciphertext, string $tag)
    {
        $this->iv         = $iv;
        $this->ciphertext = $ciphertext;
        $this->tag        = $tag;
    }
}
