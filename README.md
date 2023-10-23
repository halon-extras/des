## DES encryption and decryption

This plugin adds DES encryption and decryption function to HSL using OpenSSL.

## Installation

Follow the [instructions](https://docs.halon.io/manual/comp_install.html#installation) in our manual to add our package repository and then run the below command.

### Ubuntu

```
apt-get install halon-extras-des
```

### RHEL

```
yum install halon-extras-des
```

## Usage

### des_encrypt(message, key, mode[, options])

Encrypt a message using DES. On error none is returned.

- message (string) - the message to encrypt
- key (string) - the key as raw bytes (no padding is done)
- mode (string) - the block cipher mode of operation (cbc, ecb, cfb, ofb, ede3-cbc, ede3, ede3-cfb or ede3-ofb)
- options (array) - options array

The following options are available in the options array.

- iv (string) The initialization vector as bytes (8 bytes for cbc).
- padding (boolean) Use PKCS7 padding. The default is true.

```
import { des_encrypt } from "extras://des";

$encrypted = des_encrypt(
                        "hello world",
                        pack("a8", "my key"),
                        "cbc",
                        ["iv" => pack("x8")]
                );
```

### des_decrypt(message, key, mode[, options])

Decrypt a message using DES. On error none is returned.

- message (string) - the message to decrypt
- key (string) - the key as raw bytes (no padding is done)
- mode (string) - the block cipher mode of operation (cbc, ecb, cfb, ofb, ede3-cbc, ede3, ede3-cfb or ede3-ofb)
- options (array) - options array

The following options are available in the options array.

- iv (string) The initialization vector as bytes (8 bytes for cbc).
- padding (boolean) Use PKCS7 padding. The default is true.

```
import { des_decrypt } from "extras://des";

$message = des_decrypt(
                        $encrypted,
                        pack("a8", "my key"),
                        "cbc",
                        ["iv" => pack("x8")]
                );
```
