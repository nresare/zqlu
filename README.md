# zqlu

zqlu is a text-based format for public keys designed to be efficient and convenient. 
A key looks something like this: `zq.luAAhI0TjjRFd5K5vfy4hig23m7bppmotzOLVIkwFnPMfVWDp`

Public key cryptography algorithms based on elliptic curves have many advantages, one of them
being small key sizes. However, that benefit is not fully taken advantage of using common
key encoding methods such as OpenSSH or PEM.

Features
* Compact representation
* Using only copy-and-paste friendly characters
* Relatively easy to visually confirm the format of a key
* A checksum is added, so a corrupted key can be detected

## Credits and prior art

The design of zqlu was influenced by the [nkey](https://github.com/nats-io/nkeys) format. Thank you
for the inspiration!

## Naming

I picked zqlu because I had the idea to use a very short domain name for the magic value
at the beginning of each key. It would be unique, and if you encounter a key somewhere without
context, you can use the first five bytes as a web address and get more information about the format.
It turned out that zq.lu was available for registration, so that determined the name.

## Format

zqlu is a text-based format that encodes keys into the upper and lower case alphanumeric characters, 
numbers 0 through 9, and the period character "." as defined in the Basic Latin chart in the Unicode 
standard.

Each key consists of three parts:

* The identifier string `zq.lu`
* The key type character
* The binary key data in a key-specific encoding, concatenated with a crc16 checksum and encoded 
  with Base62

Every key starts with the string `zq.lu` identifying the format. 

The next character holds information about the type of key, or "Key Algorithm" in using the 
terminology of the ssh specifications. The table below maps keys to their equivalent SSH key.

```
A   ssh-ed25519
B   ssh-rsa
C   ecdsa-sha2-nistp256 with odd y value
D   ecdsa-sha2-nistp256 with even y value
E   ecdsa-sha2-nistp384 with odd y value
F   ecdsa-sha2-nistp384 with even y value
G   ecdsa-sha2-nistp521 with odd y value
H   ecdsa-sha2-nistp521 with even y value
I-W reserved for future use
X   extended header
Y-Z reserved for future use
```

The different variations belonging to the ECDSA family of keys map to two different 
compressed y values as described in the elliptic curve point compression scheme 
in SEC 1 Section 2.3.3.

The extended header value is a mechanism for future extensibility, where the value X indicates
that an extended header to be defined at a later date is prepended to the key data. 

### Checksum

The crd16 checksum is calculated over the first 6 characters of the key converted to bytes
using the US-ASCII character set, followed by the key bits. Once calculated, the checksum is
appended to the key data in network byte order. The specific algorithm we use is CRC-16/IBM-STLC 
as specified in RFC 1662, so the  string `123456789` should produce the value `0x906e`

Please note that this checksum algorithm will work the same even for future 
versions of this format. 

### Base62 encoding

The alphabet used for base62 encoding the binary key data uses an alphabet containing the
numbers 0-9 followed by the upper case letters A-Z and lower case letters a-z.

When encoding binary data as Base62, the key data plus checksum is treated as a big-endian
integer. This means that leading zero bytes would otherwise be lost. To preserve them, each
leading zero byte is encoded as a leading `0` character in the Base62 output, followed by the
Base62 encoding of the remaining bytes.

This follows the same general approach as the [Base58 encoding draft](https://datatracker.ietf.org/doc/html/draft-msporny-base58),
which preserves leading zero bytes using a dedicated leading character. In Base58 that
character is `1`, because `1` is the zero-valued digit in the Bitcoin Base58 alphabet. In
zqlu Base62, the corresponding character is `0`, because the alphabet begins with `0`.

### White space

Ascii whitespace characters are ignored in the key, which means that a key can be stored in a
multiline string, or even indented to match some formatting if put in say a YAML file.

## Rust usage

If you already parse SSH public keys with `ssh_key::PublicKey::from_openssh()`, the smallest
change is to switch those call sites to `zqlu::parse()`:

```rust
let public_key = zqlu::parse(input)?;
```

This returns `ssh_key::PublicKey` and accepts standard OpenSSH public key text, a `zqlu`
key, or a PEM/SPKI public key such as OpenSSL emits from `openssl ec -pubout` or
`openssl pkey -pubout`.


## License

This project is licensed under either of:

- MIT
- Apache-2.0

at your option.
