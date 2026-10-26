# Tezex
[![Build Status](https://img.shields.io/github/actions/workflow/status/objkt-com/tezex/elixir.yml?branch=main)](https://github.com/objkt-com/tezex/actions) [![Hex.pm Version](https://img.shields.io/hexpm/v/tezex.svg)](https://hex.pm/packages/tezex) [![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://hexdocs.pm/tezex/)

A collection of utils to work with the Tezos blockchain using Elixir: parsing Micheline, verifying Tezos signed messages, deriving Tezos wallet addresses from public key, etc.

Read the documentation on [hexdocs](https://hexdocs.pm/tezex/).

This lib contains a full, pure Elixir implementation of [HMAC-DRBG](https://hexdocs.pm/tezex/Tezex.Crypto.HMACDRBG.html), tested with [NIST CAPV](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) fixtures. We might extract it to a separate lib in the future.

Since what this lib provides is so far limited to what we need at [objkt.com](https://objkt.com), external contributions are most welcome.
For instance if you need to sign messages or transactions with a passphrase-protected private key, or translating Micheline to hex, we'd love to collaborate on a PR.

## Calling a contract

`Tezex.Rpc.entrypoint/3` fetches (and caches) an entrypoint's type, `Tezex.Michelson.encode/2` builds the call's parameter from an Elixir term and that type, and `Tezex.Rpc.send_operation/4` sends it:

```elixir
@contract "KT1XsH18aY2GcgSMBAdp2EzHw828iJx2WptU"
@entrypoint "transfer"
@transfer_from "tz1fFtfd49jRi4SmaeWCWMwJbikPSjGf1HKc"
@transfer_to "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew"
@secret_key "…"

rpc = %Tezex.Rpc{endpoint: "https://rpc.shadownet.teztnets.com"}
{:ok, type} = Tezex.Rpc.entrypoint(rpc, @contract, @entrypoint)

Tezex.Michelson.schema(type)
#=> {:list,
#=>  %{
#=>    "from_" => :address,
#=>    "txs" => {:list, %{"amount" => :nat, "to_" => :address, "token_id" => :nat}}
#=>  }}

value = [
  %{
    from_: @transfer_from,
    txs: [%{to_: @transfer_to, token_id: 0, amount: 1}]
  }
]

{:ok, micheline} = Tezex.Michelson.encode(type, value)

transaction = %{
  "kind" => "transaction",
  "amount" => "0",
  "destination" => @contract,
  "parameters" => %{"entrypoint" => @entrypoint, "value" => micheline}
}

# The sender is `from_`: the FA2 contract only lets the owner (or an operator)
# transfer its tokens.
{:ok, operation_hash} = Tezex.Rpc.send_operation(rpc, transaction, @transfer_from, @secret_key)
```

## Installation

The package can be installed by adding `tezex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tezex, "~> 2.0.0"}
  ]
end
```

## Requirements

OTP24 or above, it needs an elixir version that uses OTP 24 or above, for instance

```
elixir 1.14.3-otp-25
erlang 25.2.3
```

or

```
elixir 1.13.3-otp-24
erlang 24.3.4
```

## Test

```sh
$ mix test
$ mix test.watch
$ mix coveralls.html
```

## Generate Documentation

```sh
$ mix docs
```
