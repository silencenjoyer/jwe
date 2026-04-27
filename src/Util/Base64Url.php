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

namespace Silencenjoyer\Jwe\Util;

use Silencenjoyer\Jwe\Exceptions\DecodeException;

final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string
    {
        $result = base64_decode(strtr($data, '-_', '+/'), true);

        if ($result === false) {
            throw new DecodeException();
        }

        return $result;
    }
}
