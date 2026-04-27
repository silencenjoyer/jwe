<?php

/*
 * This file is part of the Encryptor package.
 *
 * (c) Andrew Gebrich <an_gebrich@outlook.com>
 *
 * For the full copyright and license information, please view the LICENSE file that was distributed with this
 * source code.
 */

namespace Silencenjoyer\Jwe\Keys;

use RuntimeException;

final class Key
{
    private string $key;
    private string $path;

    private function __construct()
    {
    }

    public static function fromPath(string $path): Key
    {
        $self = new self();

        $self->key  = file_get_contents($path);
        $self->path = $path;

        return $self;
    }

    public static function fromContent(string $content): Key
    {
        $self = new self();

        $self->key  = $content;
        $self->path = 'php://temp';

        return $self;
    }

    public function asContent(): string
    {
        return $this->key;
    }

    public function getPath(): string
    {
        return $this->path;
    }

    /**
     * @return resource
     */
    public function asResource()
    {
        $resource = fopen($this->path, 'r');

        if (!is_resource($resource)) {
            throw new RuntimeException('Invalid path provided.');
        }

        return $resource;
    }

    public function __toString(): string
    {
        return $this->asContent();
    }

    public function __debugInfo(): array
    {
        return [
            'key'  => str_repeat('*', 20),
            'path' => preg_replace('#.*/([^/]+)$#', '***/$1', $this->path),
        ];
    }
}
