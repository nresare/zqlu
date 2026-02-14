# zqlu

zqlu is a text based format for public keys that is efficient and convenient. 
A key looks something like this: zq.luCDfAuRyJiHhdUdXf6zx67HP1wg7MaLg9BJ6ghdqMSFEvx

Public key cryptography algorithms based on elliptic curves has many advantages, one of them
being small key sizes. However, that benefit is not fully taken advantage of using common
key encoding methods such as OpenSSH or PEM.

Features
* Compact representation
* Using only copy-and-paste friendly characters
* Relatively easy to visually confirm the format of a key
* A small checksum is added to detect corrupted keys

## Naming

I picked zqlu because I had the idea to use a very short domain name for the magic number
at the beginning of each key. It would be unique and if you encounter a key somewhere without
context, you can use the first 5 bytes as a web address and get more information about the format.
It turned out that zq.lu was available for registration, so that determined the name.

## Format

zqlu is a text based format that encodes keys into the upper and lower case alphanumeric characters, 
numbers 0 through 9, and the period character "." as defined in the Basic Latin chart in the Unicode 
standard.

Each key consists of 3 parts:

* The identifier string `zq.lu`
* The key type character
* The binary key data in a key specific encoding, concatenated with a crc16 checksum and encoded 
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
```

The different variations of the ECDSA family of keys maps to two different compressed y values
as described in the elliptic curve point compression scheme in SEC 1 Section 2.3.3.

### Checksum

The crd16 checksum is calculated over the first 6 characters of the key converted to bytes
using the US-ASCII character set, followed by the key bits.

### Base62 encoding

The alphabet used for base62 encoding the binary key data uses an alphabet containing the
numbers 0-9 followed by the upper case letters A-Z and lower case letters a-z.
