defmodule Tezex.Crypto.HMACDRBG do
  @moduledoc """
  Pure Elixir implementation of [HMAC-DRBG](https://csrc.nist.gov/csrc/media/events/random-number-generation-workshop-2004/documents/hashblockcipherdrbg.pdf)

  Ported from:

  > https://github.com/sorpaas/rust-hmac-drbg/blob/master/src/lib.rs
  > Apache License, Version 2.0, January 2004
  > Copyright {yyyy} {name of copyright owner}
  """
  defstruct k: <<>>, v: <<>>, count: 0

  def new(entropy, nonce, pers \\ <<>>) do
    k = for _ <- 1..32, into: <<>>, do: <<0>>
    v = for _ <- 1..32, into: <<>>, do: <<1>>
    state = %__MODULE__{k: k, v: v, count: 0}

    state
    |> update([entropy, nonce, pers])
    |> Map.put(:count, 1)
  end

  def count(state), do: state.count

  def reseed(state, entropy, add \\ <<>>) do
    update(state, [entropy, add])
  end

  def generate(state, add \\ <<>>) do
    result = for _ <- 1..32, into: <<>>, do: <<0>>
    generate_to_slice(state, result, add)
  end

  def generate_to_slice(state, result, add) do
    result = generate_bytes(state, result)

    case add do
      <<>> -> update(state, nil)
      _ -> update(state, [add])
    end

    {result, %{state | count: state.count + 1}}
  end

  defp generate_bytes(state, result) do
    Enum.reduce_while(1..10000, {0, state.v, result}, fn _, {i, v, result} ->
      if i < byte_size(result) do
        vmac = hmac(state.k)
        vmac = :crypto.mac_update(vmac, v)
        vmac = :crypto.mac_final(vmac)
        <<ex::binary-size(i), _::binary>> = result
        result = ex <> vmac
        i = i + byte_size(vmac)
        {:cont, {i, v, result}}
      else
        {:halt, result}
      end
    end)
  end

  defp update(state, seeds) do
    kmac = hmac(state.k)
    kmac = :crypto.mac_update(kmac, state.v)
    kmac = :crypto.mac_update(kmac, <<0>>)

    kmac =
      case seeds do
        nil -> kmac
        _ -> seeds |> Enum.reduce(kmac, fn seed, acc -> :crypto.mac_update(acc, seed) end)
      end

    k = :crypto.mac_final(kmac)

    vmac = hmac(k)
    vmac = :crypto.mac_update(vmac, state.v)

    v = :crypto.mac_final(vmac)

    case seeds do
      nil ->
        %__MODULE__{state | k: k, v: v}

      _ ->
        kmac = hmac(k)
        kmac = :crypto.mac_update(kmac, v)
        kmac = :crypto.mac_update(kmac, <<1>>)

        kmac =
          seeds |> Enum.reduce(kmac, fn seed, acc -> :crypto.mac_update(acc, seed) end)

        k = :crypto.mac_final(kmac)

        vmac = hmac(k)
        vmac = :crypto.mac_update(vmac, v)

        v = :crypto.mac_final(vmac)

        %__MODULE__{state | k: k, v: v}
    end
  end

  defp hmac(k) do
    :crypto.mac_init(:hmac, :sha256, k)
  end
end
