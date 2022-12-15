# Tezex
[![Build Status](https://img.shields.io/github/workflow/status/objkt-com/tezex/CI)](https://github.com/objkt-com/tezex/actions) [![Coverage Status](https://img.shields.io/coveralls/objkt-com/tezex.svg)](https://coveralls.io/github/objkt-com/tezex) [![Hex.pm Version](https://img.shields.io/hexpm/v/tezex.svg)](https://hex.pm/packages/tezex) [![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://hexdocs.pm/tezex/)

A collection of utils to work with the Tezos blockchain using Elixir: parsing Micheline, verifying Tezos signed messages, deriving Tezos wallet addresses from public key, etc.

Read the documentation on [hexdocs](https://hexdocs.pm/tezex/).

Since what this lib provides is so far limited to what we need at [objkt.com](https://objkt.com), external contributions are most welcome.
For instance if you need to sign messages or transactions, or translating Micheline to hex, we'd love to collaborate on a PR.

## Installation

The package can be installed by adding `tezex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tezex, "~> 0.1.0"}
  ]
end
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
