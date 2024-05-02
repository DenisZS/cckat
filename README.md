## cckat - CryptoCurrency Keys and Addresses Tools

A lightweight golang library for generation, format conversion and other operations on private keys, public keys and cryptocurrency addresses using the Secp256k1 elliptic curve e.g. for Bitcoin and Ethereum.

* Key generation with the possibility of using an additional source of entropy (e.g. file with random data) and mixing it with rand.Reader.
See [ https://datatracker.ietf.org/doc/html/rfc4086#section-5.1](https://datatracker.ietf.org/doc/html/rfc4086#section-5.1);
* supported private key formats: WIF, HEX, []byte, big.Int, BIP38 encrypt;
* supported public key formats: compressed, uncompressed, X-only;
* BIP38 encrypting, decrypting (no EC multiply).

Can be used in particular for cold wallets.


#### Now supported:

#### Bitcoin
* P2PKH                           - Pay to pubkey hash
* P2PKHUncomp                     - Pay to pubkey hash (uncompressed pubkey)
* P2SH                            - Pay to script hash 
* P2WPKH                          - Pay to witness pubkey hash
* P2TR                            - Pay to taproot
#### Ethereum 
* ETH                             - Ethereum address (mixed-case checksum)