# libcrypto

Echo's standard library has files, strings, and a hashmap hash. It does not have cryptography. Session tokens, password hashes, signed payloads, a message you can hand to another process without it being silently rewritten: you still need those. This module is that missing piece.

Authenticated encryption, signatures, key exchange, BLAKE2b, and Argon2id come from [Monocypher](https://monocypher.org), vendored under `c/` and compiled with the module. SHA-256, SHA-1, MD5, HMAC-SHA256, HMAC-SHA1, hex, and the constant-time compare are pure Echo. Randomness comes from libc. There is no OpenSSL to install, and there is no libsodium. The C travels with the module.

I picked Monocypher's set on purpose: XChaCha20-Poly1305, Ed25519, X25519, BLAKE2b, Argon2id. The boring, boringly correct modern ones. If a protocol names AES-GCM or RSA, this is not the library.

## A complete pass

Let's lock a message under a key and get it back, so the rest of the page has somewhere to sit:

```echo
use crypto::{secretKey, seal, open};

string $key = guard secretKey() else {
    die('no randomness');
}

string $sealed = guard seal($key, 'attack at dawn', 'user:42') else {
    die('seal failed');
}

string $plain = guard open($key, $sealed, 'user:42') else {
    die('forged or truncated');
}

echo $plain;
```

That is the whole shape: a 32 byte key, `seal`, `open`. The associated data `'user:42'` is not encrypted and not included in `$sealed`. `open` still needs the same bytes, or it fails. Use it to bind a message to its context.

`$sealed` is a string of raw bytes: the 24 byte nonce, then the ciphertext, then the 16 byte tag. Echo strings are binary-safe, so a zero byte is a byte like any other. That layout is libsodium's `crypto_aead_xchacha20poly1305_ietf` in combined mode with the nonce in front, so either side can be libsodium.

If you are coming from PHP, here is the catch: `hash('sha256', $s)` hands you hex. Everything in this module that produces bytes produces the bytes. `hex` is a separate call, on purpose. The next thing you do with a digest or a key is almost never print it.

## Installing

From your project directory:

```bash
epm add echolang/libcrypto --git https://github.com/echolang/libcrypto --range ^0.3
```

That writes a `#[requires:]` line and vendors the sources. Echo sees the `crypto` namespace as soon as the module loads. The C (Monocypher plus a tiny shim) rides along from this module's own `#[cc: sources]`. You never write a `#[cc:]` yourself.

Runs on darwin, linux and windows, matching Echo's prebuilts. Randomness is `arc4random_buf` on darwin, `getrandom` on linux and `BCryptGenRandom` on windows. The module links `bcrypt` on windows itself, so there is nothing to add on your side.

The shim exists for three things Echo should not say to Monocypher directly: Argon2's work area, an opaque BLAKE2b context, and a copy of the Ed25519 seed so Monocypher can wipe its own scratch instead of yours. Monocypher trusts the sizes it is given. The wrappers check first, because I do not.

## Authenticated encryption

`secretKey` is `random(32)`. `seal` encrypts and authenticates. `open` gives you the plaintext, or tells you the bytes were tampered with. Nothing of a forged message is returned.

```echo
string $key = guard secretKey() else {
    die('no randomness');
}

string $sealed = guard seal($key, $message) else {
    die('seal failed');
}

string $plain = guard open($key, $sealed) else ($e) {
    match ($e) {
        .forged => {
            die('tampered');
        },
        .truncated => {
            die('too short to be a sealed message');
        },
        else => {
            die('open failed');
        },
    }
}
```

The nonce is random and 24 bytes long, so a key can seal as many messages as you will ever send without a nonce repeating. Sealing the same plaintext twice produces different bytes. That is the point.

A key that is not 32 bytes is `SealError::keySize` / `OpenError::keySize`. A sealed value shorter than a nonce and a tag is `.truncated`. A bad tag, a wrong key, or the wrong associated data is `.forged`. Those are different questions, and the type keeps them apart.

```echo
crypto::KEY_BYTES     // 32
crypto::NONCE_BYTES   // 24
crypto::TAG_BYTES     // 16
```

`$sealed->size()` is `NONCE_BYTES + $message->size() + TAG_BYTES`.

## Signatures

A `SigningKey` signs. Anyone holding its 32 byte public key can `verify`. RFC 8032 Ed25519, the same bytes libsodium's `crypto_sign` produces.

```echo
use crypto::{SigningKey, verify};

SigningKey $key = guard SigningKey::generate() else {
    die('no randomness');
}

string $sig = $key->sign('hello');

if (!verify($key->publicKey(), 'hello', $sig)) {
    die('no');
}
```

`sign` is deterministic: the same key and message always give the same signature. It does not fail. `verify` is a `bool`. A public key or signature of the wrong size is simply not valid. I prefer that over a `result`, because "31 bytes" is not a special failure. It is just not a signature.

The whole secret is the 32 byte seed. Store `$key->seed()`. `restore` rebuilds the key from those 32 bytes, and hands back `null` when the seed is the wrong size:

```echo
SigningKey $key = guard SigningKey::restore($seed) else {
    die('seed is not 32 bytes');
}
```

If you have a libsodium 64 byte secret key, the first 32 bytes are this seed.

```echo
crypto::SEED_BYTES        // 32
crypto::PUBLIC_KEY_BYTES  // 32
crypto::SIGNATURE_BYTES   // 64
```

## Key exchange

Two sides each make an `ExchangeKey`, swap public keys, and `agree` on the same 32 byte secret without it ever crossing the wire. Feed that to `seal` and `open`.

```echo
use crypto::{ExchangeKey, seal, open};

ExchangeKey $alice = guard ExchangeKey::generate() else {
    die('no randomness');
}
ExchangeKey $bob = guard ExchangeKey::generate() else {
    die('no randomness');
}

string $ka = guard $alice->agree($bob->publicKey()) else {
    die('agree failed');
}
string $kb = guard $bob->agree($alice->publicKey()) else {
    die('agree failed');
}

string $sealed = guard seal($ka, 'hi bob') else {
    die('seal failed');
}
string $plain = guard open($kb, $sealed) else {
    die('open failed');
}
```

`$ka` and `$kb` are the same 32 bytes. The secret you store is `$alice->secret()`. `restore` rebuilds the key from it, the same way a signing seed works.

Here is the catch: the session key is not the raw X25519 output. That output is not uniform. `agree` runs BLAKE2b over it and both public keys in a fixed order, so the result is uniform, bound to this pair, and the same no matter which side computes it. That is libsodium's `generichash` over `crypto_scalarmult` and the two public keys, smaller first. Raw `crypto_scalarmult` on the other side will not match.

A public key that is not 32 bytes is `AgreeError::publicKeySize`. A low-order point (the all-zero public key, for example) would make the shared secret all zeros whatever our key is. Nobody honest sends one. That is `.weakKey`.

## Passwords

`hashPassword` gives you one string to store. `verifyPassword` checks a login against it. Argon2id, RFC 9106, the PHC string every Argon2 implementation reads:

```
$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
```

That is exactly what PHP's `password_hash(PASSWORD_ARGON2ID)` writes. A table filled by PHP verifies here, and the other way round.

```echo
use crypto::{hashPassword, verifyPassword, needsRehash};

string $encoded = guard hashPassword($password) else {
    die('could not hash');
}

if (!verifyPassword($password, $encoded)) {
    die('no');
}

if (needsRehash($encoded)) {
    string $again = guard hashPassword($password) else {
        die('could not hash');
    }
    // store $again
}
```

The default cost is `PasswordCost::standard()`: 64 MiB and 3 passes, RFC 9106's second recommendation on a single lane. Around a tenth of a second on a laptop, which is right for a login. Raise memory first if you want it more expensive. That is what makes GPUs and custom hardware pay.

```echo
use crypto::PasswordCost;

string $encoded = guard hashPassword($password, PasswordCost(131072, 3)) else {
    die('could not hash');
}
```

Lanes are recorded in the hash but computed on one thread here. Bumping `p` does not make this faster. It just makes a hash this process will still compute, slowly, on one core.

`verifyPassword` is a `bool`. Anything that is not a well-formed Argon2id string, or that asks for a cost outside the limits, is simply a no. `argon2i` and `argon2d` are not Argon2id. `needsRehash` is true for those too, and for a string that does not parse.

Cost limits, the ones `PasswordError::badCost` names: memory 8 KiB to 4 GiB, passes 1 to 64, lanes 1 to 16, and memory at least 8 KiB per lane. Hashing can also fail because the OS would not hand out a salt, or because there was not enough memory for the work area.

## Hashing

BLAKE2b is the hash to reach for unless something outside your program picks SHA-256. Faster in software, and a MAC on its own when given a key.

```echo
use crypto::{blake2b, sha256, hex};

echo hex(blake2b('abc'));
echo hex(blake2b('abc', 64));
echo hex(sha256('abc'));
```

`blake2b` is 32 bytes unless you say otherwise, 1 to 64. `sha256` is 32. `sha512` is 64, one-shot, from the Monocypher half that Ed25519 needs anyway.

A size or a BLAKE2b key outside 1 to 64 is a bug in the caller and stops the program. That is a `die`, not a `result`. You wrote the 0. The key did not come off the network looking like that by accident in any program I want to be in.

### Incremental

When the message arrives in pieces, the hasher classes take `update` as often as you like. `finish` hands back the digest and resets, so the same value can hash the next message.

```echo
use crypto::{Blake2b, Sha256};

Sha256 $h = Sha256();
$h->update('hello, ');
$h->update('world');
string $digest = $h->finish();

Blake2b $mac = Blake2b(key: $key);
$mac->update($header);
$mac->update($body);
string $tag = $mac->finish();
```

`Blake2b`, `Sha256`, `Sha1`, `Md5`. SHA-512 has no incremental form yet.

### HMAC

Keyed BLAKE2b is a MAC. HMAC is here for the other side that already picked a SHA.

```echo
use crypto::{blake2b, hmacSha256, hmacSha1, hmacSha512, equal};

if (!equal($got, blake2b(key: $key, $data))) {
    die('bad mac');
}

hmacSha256($key, $data)   // 32 bytes
hmacSha1($key, $data)     // 20 bytes, TOTP and HOTP
hmacSha512($key, $data)   // 64 bytes
```

A key longer than the hash's block is hashed first, as RFC 2104 says: 64 bytes for SHA-256 and SHA-1, 128 for SHA-512. HMAC is one-shot.

### SHA-1 and MD5

SHA-1 is broken for collisions. MD5 is thoroughly broken for collisions. They are here for checksums, ETags, git object ids, TOTP, and the protocols that insist on them. They are the wrong hash for anything you are inventing today.

```echo
use crypto::{sha1, md5, hex};

echo hex(sha1('abc'));
echo hex(md5('abc'));
```

## Random bytes

`random($n)` is `$n` bytes from the operating system. Good for session ids, tokens, and keys. `secretKey` is this, pinned to 32.

```echo
use crypto::random;

string $token = guard random(16) else {
    die('no randomness');
}
```

`random(0)` is an empty string, successfully. On linux, `getrandom` may return short. The wrapper loops until it has filled the buffer, or the kernel refuses. On windows, `BCryptGenRandom` takes a 32-bit length, so a request past 4 GiB goes in several calls, and a failing call hands its NTSTATUS back as `$code`.

## Hex

Lowercase, two characters per byte. `unhex` accepts either case and hands back `null` when the length is odd or a character is not a hex digit.

```echo
use crypto::{hex, unhex, sha256};

echo hex(sha256('abc'));
// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

string $raw = guard unhex('00ff10Ab') else {
    die('bad hex');
}
```

## Comparing secrets

`==` on strings can stop at the first difference. For a MAC, a token, or anything else an attacker gets to time, that is the leak. `equal` walks every byte of `$a` either way.

```echo
use crypto::equal;

if (!equal($got, $expected)) {
    die('no');
}
```

Unequal lengths are unequal, and the length itself is not treated as a secret. `verify` and `verifyPassword` already go through this. Your own HMAC check should too.

## Failures

Three shapes, on purpose.

A call that can fail at runtime returns `result<T, E>`: `random`, `secretKey`, `seal`, `open`, `agree`, `hashPassword`, `SigningKey::generate`, `ExchangeKey::generate`. `guard` is the short way through.

A yes-or-no about bytes already in hand is a `bool`: `verify`, `verifyPassword`, `equal`. Wrong size, malformed PHC, a flipped bit: no.

Absence of a well-formed value is `null`: `SigningKey::restore`, `ExchangeKey::restore`, `unhex`. `guard` unwraps those too.

A BLAKE2b size or key outside 1 to 64 is a `die`. So is running out of memory for a BLAKE2b context. Those are bugs in the caller, or the machine is done.

There is no `str::from` on the error enums yet, so interpolating one is not a sentence. Match the case you care about.

## Testing

```bash
echoc test
```

RFC vectors for XChaCha20-Poly1305, Ed25519, X25519, BLAKE2b, SHA-256, SHA-512, SHA-1, MD5, HMAC. PHP-made Argon2id strings. libsodium's session-key construction. Flipping every byte of a sealed message and a signature. No network, no extra packages. The C is the copy under `c/`.

One password test hashes at the standard 64 MiB cost. The rest of that file uses a cheap one, so the suite stays a couple of seconds.

## What is not here yet

These are deliberate postponements, not accidents.

- **AES, RSA, NIST curves.** Monocypher's set. A protocol that names those needs a different library.
- **Incremental SHA-512 and incremental HMAC.** One-shot today. `Blake2b`, `Sha256`, `Sha1`, and `Md5` already take `update`.
- **HKDF as a named function.** Keyed BLAKE2b covers "turn this secret into this many bytes."
- **Hashing a file for you.** Feed the hasher. `std::io` already opens files.
- **Locked memory, a guaranteed wipe.** Keys are ordinary Echo strings. Copy-on-write, no `mlock`. The Ed25519 shim copies the seed so Monocypher wipes scratch instead of your string, and that is as far as it goes.
- **TLS.** Plain bytes. Terminate in front, or wait.
- **Error sentences.** `"{$e}"` is not implemented for these enums.

## Where things live

| File | What it holds |
|---|---|
| `src/aead.eco` | `seal`, `open`, `secretKey`, XChaCha20-Poly1305 |
| `src/sign.eco` | `SigningKey`, `verify`, Ed25519 |
| `src/kx.eco` | `ExchangeKey`, X25519, the session-key hash |
| `src/password.eco` | Argon2id, PHC parse, `hashPassword` / `verifyPassword` |
| `src/blake2b.eco` | one-shot and incremental BLAKE2b, keyed and not |
| `src/sha256.eco` `sha1.eco` `md5.eco` | the pure-Echo hashes |
| `src/sha512.eco` | SHA-512 and HMAC-SHA512, via Monocypher |
| `src/hmac.eco` | HMAC-SHA256, HMAC-SHA1 |
| `src/random.eco` | `random`, darwin / linux / windows |
| `src/hex.eco` `equal.eco` | hex, `unhex`, constant-time compare |
| `src/monocypher.eco` | the `extern` block, `room` |
| `src/bytes.eco` | rotates, endian reads, used by the Echo hashes |
| `c/monocypher.c` `c/monocypher-ed25519.c` | Loup Vaillant's Monocypher |
| `c/shim.c` | Argon2 work area, BLAKE2b heap context, Ed25519 seed copy |

This module is MIT. Monocypher under `c/` is BSD-2-Clause or CC0 and keeps its own licence file.
