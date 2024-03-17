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
  @spec init(iodata(), iodata(), iodata() | nil) :: t()
  def init(entropy, nonce, pers \\ nil) do
    k = for _ <- 1..32, into: <<>>, do: <<0>>
    v = for _ <- 1..32, into: <<>>, do: <<1>>
    state = %__MODULE__{k: k, v: v, count: 0}

    seed =
      [entropy, nonce, pers]
      |> Enum.reject(&is_nil/1)
      |> Enum.join()
      |> :binary.encode_hex()

    state = update(state, seed)
    %{state | count: 1}
  end

  @spec update(t(), binary | nil) :: t()
  defp update(state, seed) do
    seed = if is_nil(seed), do: nil, else: :binary.decode_hex(seed)

    kmac =
      hmac(state.k)
      |> :crypto.mac_update(state.v)
      |> :crypto.mac_update(<<0>>)

    kmac =
      if is_nil(seed) do
        kmac
      else
        :crypto.mac_update(kmac, seed)
      end

    k = :crypto.mac_final(kmac)

    v =
      hmac(k)
      |> :crypto.mac_update(state.v)
      |> :crypto.mac_final()

    if is_nil(seed) do
      %{state | k: k, v: v}
    else
      kmac =
        hmac(k)
        |> :crypto.mac_update(v)
        |> :crypto.mac_update(<<1>>)

      kmac = :crypto.mac_update(kmac, seed)

      k = :crypto.mac_final(kmac)

      v = hmac(k) |> :crypto.mac_update(v) |> :crypto.mac_final()

      # d("#{source} update with", seed)
      # d(v)
      %{state | k: k, v: v}
    end
  end

  @spec reseed(t(), iodata()) :: t()
  @spec reseed(t(), iodata(), iodata() | nil) :: t()
  def reseed(state, entropy, add \\ nil) do
    seed =
      [entropy, add]
      |> Enum.reject(&is_nil/1)
      |> Enum.join("")
      |> :binary.encode_hex()

    update(state, seed)
  end

  @spec generate(t(), pos_integer()) :: {binary(), t()}
  @spec generate(t(), pos_integer(), iodata() | nil) :: {binary(), t()}
  def generate(state, size, add \\ nil) do
    state =
      case add do
        nil -> state
        _ -> update(state, add)
      end

    {v, result} = generate_bytes(state, size)
    state = %{state | v: v}

    state = update(state, add)

    {result, %{state | count: state.count + 1}}
  end

  defp generate_bytes(state, size) do
    Enum.reduce_while(1..10000, {state.v, <<>>}, fn _i, {v, result} ->
      if byte_size(result) < size / 2 do
        v =
          hmac(state.k)
          |> :crypto.mac_update(v)
          |> :crypto.mac_final()

        {:cont, {v, result <> v}}
      else
        {:halt, {v, result}}
      end
    end)
  end

  defp hmac(k) do
    :crypto.mac_init(:hmac, :sha256, k)
  end
end
