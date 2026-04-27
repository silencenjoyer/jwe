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

use Silencenjoyer\Jwe\Keys\Key;

/**
 * JWE "dir" key decapsulation (RFC 7518 §4.5).
 *
 * Returns the pre-shared key directly, ignoring the encrypted_key field.
 */
class DirectKeyUnwrapper implements KeyUnwrapperInterface
{
    private const ALGO = 'dir';

    private Key $sharedKey;

    public function __construct(Key $sharedKey)
    {
        $this->sharedKey = $sharedKey;
    }

    public function getAlgorithm(): string
    {
        return self::ALGO;
    }

    public function unwrap(string $wrapped): string
    {
        return $this->sharedKey->asContent();
    }
}
