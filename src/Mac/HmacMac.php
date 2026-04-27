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

namespace Silencenjoyer\Jwe\Mac;

/**
 * HMAC-based content authentication for JWE CBC-HMAC algorithms (RFC 7518 §5.2.2).
 *
 * Covers A128CBC-HS256 (sha256, tagSize=16), A192CBC-HS384 (sha384, tagSize=24),
 * and A256CBC-HS512 (sha512, tagSize=32).
 *
 * MAC input: AAD || IV || ciphertext || AL, where AL is len(AAD) in bits as 64-bit big-endian.
 */
final class HmacMac
{
    private string $macKey;
    private string $algo;
    private int    $tagSize;

    public function __construct(string $macKey, string $algo, int $tagSize)
    {
        $this->macKey  = $macKey;
        $this->algo    = $algo;
        $this->tagSize = $tagSize;
    }

    public function sign(string $aad, string $iv, string $ciphertext): string
    {
        $al  = pack('N2', 0, strlen($aad) * 8);
        $mac = hash_hmac($this->algo, $aad . $iv . $ciphertext . $al, $this->macKey, true);

        return substr($mac, 0, $this->tagSize);
    }

    public function verify(string $aad, string $iv, string $ciphertext, string $tag): bool
    {
        return hash_equals($this->sign($aad, $iv, $ciphertext), $tag);
    }
}
