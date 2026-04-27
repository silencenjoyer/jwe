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

use Silencenjoyer\Jwe\Exceptions\DecodeException;
use Silencenjoyer\Jwe\Util\Base64Url;

final class JweHeader
{
    private string $alg;
    private string $enc;

    public function __construct(string $alg, string $enc)
    {
        $this->alg = $alg;
        $this->enc = $enc;
    }

    public static function fromEncoded(string $protectedHeader): self
    {
        $json = Base64Url::decode($protectedHeader);
        $data = json_decode($json, true);

        if (!is_array($data) || !isset($data['alg'], $data['enc'])) {
            throw new DecodeException();
        }

        return new self((string) $data['alg'], (string) $data['enc']);
    }

    public function encode(): string
    {
        $json = json_encode(['alg' => $this->alg, 'enc' => $this->enc], JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new DecodeException();
        }

        return Base64Url::encode($json);
    }

    public function getAlg(): string
    {
        return $this->alg;
    }

    public function getEnc(): string
    {
        return $this->enc;
    }
}
