# BRP256v1
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/brp256v1/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/brp256v1?status.png)](http://godoc.org/github.com/pedroalbanese/brp256v1)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/brp256v1)](https://goreportcard.com/report/github.com/pedroalbanese/brp256v1)

Parameters for the BRP256v1 Elliptic curve

### Usage
```
Usage of brp256v1:
  -bits int
        Shared secret bit-length. (default 128)
  -decrypt
        Decrypt with Privatekey.
  -derive
        Derive shared secret.
  -encrypt
        Encrypt with Publickey.
  -key string
        Private/Public key depending on operation.
  -keygen
        Generate keypair.
  -pub string
        Remote's side Public key. (for ECDH)
  -sign
        Sign with Private key.
  -signature string
        Signature.
  -verify
        Verify with Public key.
```
### TODO
- [ ] 512-bit

## License

This project is licensed under the ISC License.

##### Industrial-Grade Reliability. Copyright (c) 2020-2023 ALBANESE Research Lab.
