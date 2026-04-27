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

interface KeyWrapperInterface
{
    public function getAlgorithm(): string;

    /**
     * Generate a CEK and encapsulate it.
     *
     * @param int $cekSize
     *
     * @return WrappedKeyDto
     */
    public function wrap(int $cekSize): WrappedKeyDto;
}
