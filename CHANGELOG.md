# Changelog for Tezex


## v1.2.0

- [micheline]: add `decode_optimized_address/1` to decode the optimized Micheline representation of an address value

## v1.1.0

- [crypto]: add `encode_pubkey/2` to generate public key from raw hex pubkey

## v1.0.0

- [crypto]: remove dependency on NIF libsecp256k1
- [crypto]: remove dependency on NIF enacl (libsodium)
- [crypto]: make `Tezex.Crypto.check_signature/4` return a tuple instead of a boolean

## v0.1.0

- initial release
