# Changelog for Tezex

## v2.0.0

- [BREAKING]: `Tezex.Micheline` now only takes care of `PACK`ing and `UNPACK`ing, forging and unforging is now in `Tezex.Forge`
- [BREAKING]: `Tezex.Micheline.Zarith` is replaced with `Tezex.Zarith`
- [crypto] add a pure Elixir [HMAC-DRBG](https://hexdocs.pm/tezex/Tezex.Crypto.HMACDRBG.html) implementation
- [crypto] implement message/operations [signing](https://hexdocs.pm/tezex/Tezex.Crypto.html#sign_message/2)
- [crypto] implement [validate_address/1](https://hexdocs.pm/tezex/Tezex.Crypto.html#validate_address/1) to validate implicit account addresses
- implement (un)forging [micheline](https://hexdocs.pm/tezex/Tezex.Forge.html), [operations/operation groups](https://hexdocs.pm/tezex/Tezex.ForgeOperation.html), [calculating gas/storage/fees](https://hexdocs.pm/tezex/Tezex.Fee.html) and [sending them to Tezos RPC nodes](https://hexdocs.pm/tezex/Tezex.Rpc.html).

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
