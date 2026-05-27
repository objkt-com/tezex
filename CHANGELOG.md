# Changelog for Tezex

## v5.0.0

- [BREAKING][forge_operation]: error returns changed from `{:error, String.t()}` to `{:error, {:missing_keys, [String.t()]}}` (affects `validate_required_keys/3`, `operation/1`, `operation_group/1` and all per-operation builders)
- [BREAKING][fee]: `calculate_fee/3` error shape changed accordingly (propagated from `forge_operation`)
- [BREAKING][rpc]: unified all error returns to `{:error, {reason, detail}}` — transport errors are wrapped (`:transport`, `:http_status`, `:decode`); preapply returns `{:preapply_failed, errors}` / `{:unexpected_response, body}`; `fill_operation_fee/3` now returns `{:ok, operation} | {:error, _}` (previously crashed on fee errors); `get_counter_for_account/2` now returns `{:ok, integer()} | {:error, _}`; `get_balance/2` returns `{:error, {:invalid_balance, _}}` instead of raising on a non-integer body; `get_block_at_offset/2` returns `{:error, _}` instead of raising on a transport error, and now short-circuits to the head block for `offset <= 0`
- [BREAKING][crypto/bls]: drop `is_` prefix from predicates (`is_zero?` → `zero?`, `is_one?` → `one?`, `is_infinity?` → `infinity?`) across `Fq`, `Fr`, `Fq2`, `Fq12`, `FqP`, `G1`, `G2`
- [BREAKING][crypto/bls]: `Fq12.inv/1` and `FqP.inv/1` now return `{:ok, t} | {:error, :not_invertible}`
- [BREAKING][crypto/bls]: `Fr.from_bytes/1` rejects out-of-range scalars with `:out_of_range` instead of silently reducing
- [zarith]: raise `ArgumentError` on malformed/truncated hex input
- [forge_operation]: fix `endorsement/1`, `endorsement_with_slot/1`, `failing_noop/1` (were passing the kind string to `forge_tag` and raising `ArgumentError`)
- [crypto/private_key]: `from_encoded_key!/2` preserves the underlying error instead of masking everything as `invalid_base58`
- [crypto/math]: `mod_inverse/2` handles negative input
- [crypto/bls]: validate scalars in `Fr.from_bytes/1`, fix `Fq.sqrt/1` zero case, handle negative input in `Fq.from_integer/1`, use `from_integer` reduction in `BLS.from_seed/1`
- [crypto/ecdsa]: fix `k` upper-bound check in signature generation (was comparing integer to binary, always false)
- [crypto/nacl]: fix `crypto_secretbox_open/3` typespec to include `:invalid_nonce_length` and `:invalid_key_length`
- [crypto/bls]: pre-compute Miller loop bits in pairing for faster verification

## v4.0.0

- [BREAKING]: `Tezex.Rpc.get_counter_for_account/2` now returns a tuple
- [rpc]: prevent crash when counter result is not an integer

## v3.2.0

- [crypto] add a pure Elixir [BLS12-381](https://hexdocs.pm/tezex/Tezex.Crypto.BLS.html) implementation
- [crypto] implement signing with encrypted p256 key
- [crypto] implement tz4 (BLS12-381) support

## v3.1.0

- [rpc]: adapt constants to Rio protocol update

## v3.0.1

- [rpc]: prevent crash when preapply result is not a list

## v3.0.0

- [BREAKING]: `Tezex.Fee.calculate_fee/2` now returns a tuple
- [BREAKING]: `Tezex.Rpc.forge_and_sign_operation/2` now returns a tuple
- Refactor `Tezex.Fee`, `Tezex.ForgeOperation` and `Tezex.Rpc` to return tuples instead of crashing on assertions

## v2.0.0

- [BREAKING]: `Tezex.Micheline` now only takes care of `PACK`ing and `UNPACK`ing, forging and unforging is now in `Tezex.Forge`
- [BREAKING]: `Tezex.Micheline.Zarith` is replaced with `Tezex.Zarith`
- [crypto] add a pure Elixir [HMAC-DRBG](https://hexdocs.pm/tezex/Tezex.Crypto.HMACDRBG.html) implementation
- [crypto] implement message/operations [signing](https://hexdocs.pm/tezex/Tezex.Crypto.html#sign_message/2)
- [crypto] implement [validate_address/1](https://hexdocs.pm/tezex/Tezex.Crypto.html#validate_address/1) to validate implicit account addresses
- implement: 
  - (un)forging [micheline](https://hexdocs.pm/tezex/Tezex.Forge.html), [operations/operation groups](https://hexdocs.pm/tezex/Tezex.ForgeOperation.html)
  - [calculating gas/storage/fees](https://hexdocs.pm/tezex/Tezex.Fee.html)
  - [sending transactions to Tezos RPC nodes](https://hexdocs.pm/tezex/Tezex.Rpc.html)

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
