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

use Silencenjoyer\Jwe\JweToken;

interface DecryptorInterface
{
    public function decrypt(JweToken $token): string;
}
