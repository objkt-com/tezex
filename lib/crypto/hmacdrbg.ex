defmodule Tezex.Crypto.HMACDRBG do
  @moduledoc """
  Pure Elixir implementation of [HMAC-DRBG](https://csrc.nist.gov/csrc/media/events/random-number-generation-workshop-2004/documents/hashblockcipherdrbg.pdf)

  Ported from:

  > https://github.com/sorpaas/rust-hmac-drbg/blob/master/src/lib.rs
  > Apache License, Version 2.0, January 2004
  > Copyright {yyyy} {name of copyright owner}
  """

  @type t :: %__MODULE__{
          k: binary(),
          v: binary(),
          count: non_neg_integer()
        }

  defstruct k: <<>>, v: <<>>, count: 0

  @spec init(iodata(), iodata()) :: t()
  @spec init(iodata(), iodata(), iodata()) :: t()
  def init(entropy, nonce, pers \\ <<>>) do
    k = for _ <- 1..32, into: <<>>, do: <<0>>
    v = for _ <- 1..32, into: <<>>, do: <<1>>
    state = %__MODULE__{k: k, v: v, count: 0}

    state = update(state, [entropy, nonce, pers])
    %{state | count: 1}
  end

  @spec count(t()) :: non_neg_integer()
  def count(state), do: state.count

  @spec reseed(t(), iodata()) :: t()
  @spec reseed(t(), iodata(), iodata()) :: t()
  def reseed(state, entropy, add \\ <<>>) do
    update(state, [entropy, add])
  end

  @spec generate(t()) :: {binary(), t()}
  @spec generate(t(), iodata()) :: {binary(), t()}
  def generate(state, add \\ <<>>) do
    result = for _ <- 1..32, into: <<>>, do: <<0>>
    generate_to_slice(state, result, add)
  end

  @spec generate_to_slice(t(), iodata(), iodata()) :: {binary(), t()}
  def generate_to_slice(state, result, add) do
    result = generate_bytes(state, result)

    case add do
      <<>> -> update(state, nil)
      _ -> update(state, [add])
    end

    {result, %{state | count: state.count + 1}}
  end

  @spec generate(t()) :: binary()
  defp generate_bytes(state, result) do
    Enum.reduce_while(1..10000, {0, state.v, result}, fn _, {i, v, result} ->
      if i < byte_size(result) do
        vmac = hmac(state.k)
        vmac = :crypto.mac_update(vmac, v)
        vmac = :crypto.mac_final(vmac)
        <<ex::binary-size(i), _::binary>> = result
        {:cont, {i + byte_size(vmac), v, ex <> vmac}}
      else
        {:halt, result}
      end
    end)
  end

  @spec generate(t(), list(binary())) :: t()
  defp update(state, seeds) do
    kmac = hmac(state.k)
    kmac = :crypto.mac_update(kmac, state.v)
    kmac = :crypto.mac_update(kmac, <<0>>)

    kmac =
      if is_nil(seeds) do
        kmac
      else
        Enum.reduce(seeds, kmac, &:crypto.mac_update(&2, &1))
      end

    k = :crypto.mac_final(kmac)

    v =
      hmac(k)
      |> :crypto.mac_update(state.v)
      |> :crypto.mac_final()

    if is_nil(seeds) do
      %{state | k: k, v: v}
    else
      kmac =
        hmac(k)
        |> :crypto.mac_update(v)
        |> :crypto.mac_update(<<1>>)

      kmac = Enum.reduce(seeds, kmac, &:crypto.mac_update(&2, &1))

      k = :crypto.mac_final(kmac)

      v =
        hmac(k)
        |> :crypto.mac_update(v)
        |> :crypto.mac_final()

      %{state | k: k, v: v}
    end
  end

  defp hmac(k) do
    :crypto.mac_init(:hmac, :sha256, k)
  end
end
