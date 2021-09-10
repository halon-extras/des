## DES encryption and decryption

This plugin adds DES encryption and decryption function to HSL using OpenSSL.

### des_encrypt(message, key, mode[, options])

Decrypt a message using DES. On error none is returned.

- message (string) – the message to encrypt
- key (string) – the key as raw bytes (no padding is done)
- mode (string) – the block cipher mode of operation (cbc, ecb, cfb, ofb, ede3-cbc, ede3, ede3-cfb or ede3-ofb)
- options (array) – options array

The following options are available in the options array.

- iv (string) The initialization vector as bytes (8 bytes for cbc).
- padding (boolean) Use PKCS7 padding. The default is true.

```
$encrypted = des_encrypt(
                        "hello world",
                        pack("a8", "my key"),
                        "cbc",
                        ["iv" => pack("x8")]
                );
```

### des_decrypt(message, key, mode[, options])

Decrypt a message using DES. On error none is returned.

- message (string) – the message to decrypt
- key (string) – the key as raw bytes (no padding is done)
- mode (string) – the block cipher mode of operation (cbc, ecb, cfb, ofb, ede3-cbc, ede3, ede3-cfb or ede3-ofb)
- options (array) – options array

The following options are available in the options array.

- iv (string) The initialization vector as bytes (8 bytes for cbc).
- padding (boolean) Use PKCS7 padding. The default is true.

```
$message = des_decrypt(
                        $encrypted,
                        pack("a8", "my key"),
                        "cbc",
                        ["iv" => pack("x8")]
                );
```