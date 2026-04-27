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

namespace Silencenjoyer\Jwe;

/**
 * Immutable value object representing a JWE token (RFC 7516).
 *
 * All string fields are base64url-encoded as required by the spec.
 * The protectedHeader field doubles as AAD for the content cipher.
 */
class JweToken
{
    public string $protectedHeader;
    public string $encryptedKey;
    public string $iv;
    public string $ciphertext;
    public string $tag;

    public function __construct(
        string $protectedHeader,
        string $encryptedKey,
        string $iv,
        string $ciphertext,
        string $tag
    ) {
        $this->protectedHeader = $protectedHeader;
        $this->encryptedKey    = $encryptedKey;
        $this->iv              = $iv;
        $this->ciphertext      = $ciphertext;
        $this->tag             = $tag;
    }
}
