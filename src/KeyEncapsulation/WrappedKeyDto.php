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

final class WrappedKeyDto
{
    private string $cek;
    private string $encryptedKey;

    public function __construct(string $cek, string $encryptedLey)
    {
        $this->cek = $cek;
        $this->encryptedKey = $encryptedLey;
    }

    public function getCek(): string
    {
        return $this->cek;
    }

    public function getEncryptedKey(): string
    {
        return $this->encryptedKey;
    }
}
