defmodule Tezex.Crypto.HMACDRBG do
  @moduledoc """
  Pure Elixir implementation of [HMAC-DRBG](https://csrc.nist.gov/csrc/media/events/random-number-generation-workshop-2004/documents/hashblockcipherdrbg.pdf)

  Usage:
  ```
  entropy = "totally random0123456789"
  nonce = "some secret nonce"
  pers = "my drbg"
  drbg = HMACDRBG.init(entropy, nonce, pers)

  {_result, drbg} = HMACDRBG.generate(drbg, 32)
  {_result, drbg} = HMACDRBG.generate(drbg, 32)
  {result, drbg} = HMACDRBG.generate(drbg, 32)

  Base16.encode(result, case: :lower) == "a00cb0982eec3917b4b48abccfd460366d98b887943ff402bb7147cda174a46f"
  ```

  Implementation inspired by both:

  > https://github.com/indutny/hmac-drbg/blob/master/package.json
  >
  > MIT / (c) Fedor Indutny <fedor@indutny.com>

  > https://github.com/sorpaas/rust-hmac-drbg/blob/master/src/lib.rs
  >
  > Apache License, Version 2.0, January 2004 / Copyright {yyyy} {name of copyright owner}
  """

  @type hash_algo ::
          :sha
          | :sha224
          | :sha256
          | :sha384
          | :sha512
          | :sha3_224
          | :sha3_256
          | :sha3_384
          | :sha3_512
  @type t :: %__MODULE__{
          k: binary(),
          v: binary(),
          count: non_neg_integer(),
          algo: hash_algo()
        }

  defstruct k: <<>>, v: <<>>, count: 0, algo: :sha256

  @doc """
  Initialize a DRBG
  """
  @spec init(binary(), binary()) :: t()
  @spec init(binary(), binary(), binary() | nil) :: t()
  @spec init(binary(), binary(), binary() | nil, hash_algo()) :: t()
  def init(entropy, nonce, pers \\ nil, algo \\ :sha256) do
    k = for _ <- 1..32, into: <<>>, do: <<0>>
    v = for _ <- 1..32, into: <<>>, do: <<1>>
    state = %__MODULE__{k: k, v: v, count: 0, algo: algo}

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

    k =
      :crypto.mac_init(:hmac, state.algo, state.k)
      |> :crypto.mac_update(state.v)
      |> :crypto.mac_update(<<0>>)
      |> then(fn kmac ->
        if is_nil(seed) do
          kmac
        else
          :crypto.mac_update(kmac, seed)
        end
      end)
      |> :crypto.mac_final()

    v =
      :crypto.mac_init(:hmac, state.algo, k)
      |> :crypto.mac_update(state.v)
      |> :crypto.mac_final()

    if is_nil(seed) do
      %{state | k: k, v: v}
    else
      k =
        :crypto.mac_init(:hmac, state.algo, k)
        |> :crypto.mac_update(v)
        |> :crypto.mac_update(<<1>>)
        |> :crypto.mac_update(seed)
        |> :crypto.mac_final()

      v =
        :crypto.mac_init(:hmac, state.algo, k)
        |> :crypto.mac_update(v)
        |> :crypto.mac_final()

      %{state | k: k, v: v}
    end
  end

  @doc """
  Reseed a DRBG
  """
  @spec reseed(t(), binary()) :: t()
  @spec reseed(t(), binary(), binary() | nil) :: t()
  def reseed(state, entropy, add \\ nil) do
    seed =
      [entropy, add]
      |> Enum.reject(&is_nil/1)
      |> Enum.join("")
      |> :binary.encode_hex()

    update(state, seed)
  end

  @doc """
  Generate `size` bytes, returning the generated bytes and the updated DRBG
  """
  @spec generate(t(), pos_integer()) :: {binary(), t()}
  @spec generate(t(), pos_integer(), binary() | nil) :: {binary(), t()}
  def generate(state, size, add \\ nil) do
    state =
      case add do
        nil -> state
        _ -> update(state, add)
      end

    {state, result} = generate_bytes(state, size, <<>>)

    state = update(state, add)

    {result, %{state | count: state.count + 1}}
  end

  defp generate_bytes(state, size, result) when byte_size(result) < size / 2 do
    v =
      :crypto.mac_init(:hmac, state.algo, state.k)
      |> :crypto.mac_update(state.v)
      |> :crypto.mac_final()

    generate_bytes(%{state | v: v}, size, result <> v)
  end

  defp generate_bytes(state, _size, result) do
    {state, result}
  end
end
