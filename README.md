# Tezex
[![Build Status](https://img.shields.io/github/actions/workflow/status/objkt-com/tezex/elixir.yml?branch=main)](https://github.com/objkt-com/tezex/actions) [![Hex.pm Version](https://img.shields.io/hexpm/v/tezex.svg)](https://hex.pm/packages/tezex) [![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://hexdocs.pm/tezex/)

A collection of utils to work with the Tezos blockchain using Elixir: parsing Micheline, verifying Tezos signed messages, deriving Tezos wallet addresses from public key, etc.

Read the documentation on [hexdocs](https://hexdocs.pm/tezex/).

Since what this lib provides is so far limited to what we need at [objkt.com](https://objkt.com), external contributions are most welcome.
For instance if you need to sign messages or transactions, or translating Micheline to hex, we'd love to collaborate on a PR.

## Installation

The package can be installed by adding `tezex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tezex, "~> 1.0.0"}
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
