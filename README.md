# 🔐 silencenjoyer/jwe

[![Tests](https://github.com/silencenjoyer/jwe/actions/workflows/tests.yml/badge.svg)](https://github.com/silencenjoyer/jwe/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/silencenjoyer/jwe/branch/main/graph/badge.svg)](https://codecov.io/gh/silencenjoyer/jwe)
[![Static Analyze](https://github.com/silencenjoyer/jwe/actions/workflows/phpstan.yml/badge.svg)](https://github.com/silencenjoyer/jwe/actions/workflows/phpunit.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/silencenjoyer/jwe.svg)](https://packagist.org/packages/silencenjoyer/jwe)
[![PHP Version Require](https://img.shields.io/packagist/php-v/silencenjoyer/jwe.svg)](https://packagist.org/packages/silencenjoyer/jwe)
[![License](https://img.shields.io/github/license/silencenjoyer/jwe)](LICENSE)

A PHP library for JSON Web Encryption (JWE) as defined in [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516).

Supports symmetric shared-key and asymmetric RSA end-to-end encryption, multiple content encryption algorithms, and both JWE Compact and JSON serialization formats.

## Requirements

- PHP 7.4 or 8.0+
- `ext-openssl`
- `ext-json`

## Installation

```bash
composer require silencenjoyer/jwe
```

## Supported algorithms

| Role | Identifier | Class | Description |
|---|---|---|---|
| Key encapsulation | `dir` | `DirectKeyWrapper` / `DirectKeyUnwrapper` | Shared symmetric key used directly as CEK |
| Key encapsulation | `RSA-OAEP` | `RsaKeyWrapper` / `RsaKeyUnwrapper` | CEK encrypted with recipient's RSA public key |
| Content encryption | `A256GCM` | `Aes256GcmFactory` | AES-256 in GCM mode (32-byte CEK) |
| Content encryption | `A256CBC-HS512` | `Aes256CbcFactory` | AES-256 in CBC mode with HMAC-SHA-512 (64-byte CEK) |

## Usage

### Symmetric encryption (shared secret)

Both parties share the same secret key. The key is used directly as the Content Encryption Key (CEK), so `encrypted_key` in the JWE token is empty.

```php
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256GcmFactory;
use Silencenjoyer\Jwe\Decryptors\Decryptor;
use Silencenjoyer\Jwe\Encryptors\Encryptor;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyUnwrapper;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyWrapper;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Serializers\CompactSerializer;

// A 32-byte shared secret for A256GCM (use 64 bytes for A256CBC-HS512)
$sharedKey = Key::fromContent('a-32-byte-secret-key-goes-here!!');

$encryptor = new Encryptor(
    new DirectKeyWrapper($sharedKey),
    new Aes256GcmFactory(),
);

$decryptor = new Decryptor(
    new DirectKeyUnwrapper($sharedKey),
    new Aes256GcmFactory(),
);

$serializer = new CompactSerializer();

// Encrypt
$token     = $encryptor->encrypt('Hello, World!');
$compactJwe = $serializer->serialize($token);
// eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0...<iv>.<ciphertext>.<tag>

// Decrypt
$plaintext = $decryptor->decrypt($serializer->unserialize($compactJwe));
// "Hello, World!"
```

---

### RSA end-to-end encryption

The sender encrypts a random CEK with the recipient's **public** RSA key. Only the holder of the matching **private** key can recover the CEK and decrypt the content. No shared secret is required.

```php
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256GcmFactory;
use Silencenjoyer\Jwe\Decryptors\Decryptor;
use Silencenjoyer\Jwe\Encryptors\Encryptor;
use Silencenjoyer\Jwe\KeyEncapsulation\RsaKeyUnwrapper;
use Silencenjoyer\Jwe\KeyEncapsulation\RsaKeyWrapper;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Serializers\CompactSerializer;

$publicKey  = Key::fromPath('/path/to/public.pem');
$privateKey = Key::fromPath('/path/to/private.pem');

// Sender side: encrypt with recipient's public key
$encryptor = new Encryptor(
    new RsaKeyWrapper($publicKey),
    new Aes256GcmFactory(),
);

$serializer = new CompactSerializer();
$compactJwe  = $serializer->serialize($encryptor->encrypt('Secret message'));

// Recipient side: decrypt with own private key
$decryptor = new Decryptor(
    new RsaKeyUnwrapper($privateKey),
    new Aes256GcmFactory(),
);

$plaintext = $decryptor->decrypt($serializer->unserialize($compactJwe));
// "Secret message"
```

To generate a key pair:

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

---

### AutoDecryptor — algorithm-agnostic decryption

`AutoDecryptor` reads the algorithm identifiers from the JWE protected header at runtime and selects the correct unwrapper and cipher automatically. Register the algorithms you want to support once, then decrypt any compatible token.

```php
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256CbcFactory;
use Silencenjoyer\Jwe\Ciphers\Factory\Aes256GcmFactory;
use Silencenjoyer\Jwe\Decryptors\AutoDecryptor;
use Silencenjoyer\Jwe\KeyEncapsulation\DirectKeyUnwrapper;
use Silencenjoyer\Jwe\KeyEncapsulation\RsaKeyUnwrapper;
use Silencenjoyer\Jwe\Keys\Key;
use Silencenjoyer\Jwe\Serializers\CompactSerializer;

$privateKey = Key::fromPath('/path/to/private.pem');
$sharedKey  = Key::fromContent('a-32-byte-secret-key-goes-here!!');

$decryptor = (new AutoDecryptor())
    // Key encapsulation algorithms
    ->addUnwrapper(new RsaKeyUnwrapper($privateKey))   // handles alg=RSA-OAEP
    ->addUnwrapper(new DirectKeyUnwrapper($sharedKey)) // handles alg=dir
    // Content encryption algorithms
    ->addCipherFactory(new Aes256GcmFactory())         // handles enc=A256GCM
    ->addCipherFactory(new Aes256CbcFactory());        // handles enc=A256CBC-HS512

$serializer = new CompactSerializer();

// Works for any combination of the registered algorithms
$plaintext = $decryptor->decrypt($serializer->unserialize($compactJwe));
```

If the token uses an algorithm that was not registered, `UnsupportedAlgorithmException` is thrown.

---

### Serialization formats

The library supports both JWE serialization formats defined in RFC 7516.

**Compact serialization** — five base64url parts separated by dots, suitable for HTTP headers and URLs:

```php
use Silencenjoyer\Jwe\Serializers\CompactSerializer;

$serializer = new CompactSerializer();
$compact    = $serializer->serialize($token);   // "header.enckey.iv.ciphertext.tag"
$token      = $serializer->unserialize($compact);
```

**JSON serialization** — a JSON object, easier to inspect and log:

```php
use Silencenjoyer\Jwe\Serializers\JsonSerializer;

$serializer = new JsonSerializer();
$json       = $serializer->serialize($token);
// {
//   "protected": "...",
//   "encrypted_key": "...",
//   "iv": "...",
//   "ciphertext": "...",
//   "tag": "..."
// }
$token = $serializer->unserialize($json);
```

---

### Loading keys

```php
use Silencenjoyer\Jwe\Keys\Key;

// From a PEM file on disk
$key = Key::fromPath('/path/to/key.pem');

// From a string (e.g. an environment variable or a secrets manager)
$key = Key::fromContent(getenv('SHARED_SECRET'));
```

## ⚒️ Code Quality:
- Tests: ``composer test``
- Static analysis: ``composer phpstan``
- PSR-12 formatting

## License

MIT
