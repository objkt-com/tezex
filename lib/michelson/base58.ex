defmodule Tezex.Michelson.Base58 do
  @moduledoc """
  Validates the base58 literals of Michelson's address-like types and decodes
  them into the binary forms the protocol compares them by.

  Prefixes are Octez's: src/lib_crypto/base58.ml, plus contract_hash.ml (KT1)
  and zk_rollup_repr.ml (epx1) in the protocol.
  """

  alias Tezex.Crypto.Base58Check

  @spec decode(String.t(), String.t()) :: {:ok, term()} | :error
  def decode("address", value), do: address(value)
  def decode("contract", value), do: address(value)
  def decode("key_hash", value), do: key_hash(value)
  def decode("key", value), do: key(value)
  def decode("signature", value), do: signature(value)
  def decode("chain_id", value), do: chain_id(value)

  @doc """
  An address is compared by destination, then by entrypoint name, where no
  entrypoint means `"default"` (script_comparable.ml, `compare_address`).
  Destinations are tagged like their binary encoding (destination_repr.ml), so
  their byte order is the protocol's: implicit (tz1 < tz2 < tz3 < tz4) < KT1 <
  sr1 < epx1.
  """
  @spec address(String.t()) :: {:ok, {binary(), String.t()}} | :error
  def address(value) do
    with {:ok, address, entrypoint} <- split_entrypoint(value),
         {:ok, payload} <- payload(address),
         {:ok, destination} <- destination(payload) do
      {:ok, {destination, entrypoint}}
    end
  end

  @spec key_hash(String.t()) :: {:ok, binary()} | :error
  def key_hash(value) do
    with {:ok, payload} <- payload(value) do
      implicit(payload)
    end
  end

  @doc """
  A key is compared by curve (ed25519 < secp256k1 < p256 < bls), then by key
  bytes (signature_v1.ml). The bytes here are the encoded ones; p256 keys need
  decompressing before they're compared, see `Tezex.Michelson.Comparable`.
  """
  @spec key(String.t()) :: {:ok, {0..3, binary()}} | :error
  def key(value) do
    case payload(value) do
      {:ok, <<13, 15, 37, 217, key::binary-size(32)>>} ->
        {:ok, {0, key}}

      {:ok, <<3, 254, 226, 86, parity, x::binary-size(32)>>} when parity in [2, 3] ->
        {:ok, {1, <<parity, x::binary>>}}

      {:ok, <<3, 178, 139, 127, parity, x::binary-size(32)>>} when parity in [2, 3] ->
        {:ok, {2, <<parity, x::binary>>}}

      {:ok, <<6, 149, 135, 204, key::binary-size(48)>>} ->
        {:ok, {3, key}}

      _ ->
        :error
    end
  end

  @doc """
  A signature is compared by its raw bytes, whatever its prefix
  (signature_v1.ml), so `edsig…` and `sig…` with the same bytes are equal.
  """
  @spec signature(String.t()) :: {:ok, binary()} | :error
  def signature(value) do
    case payload(value) do
      {:ok, <<9, 245, 205, 134, 18, signature::binary-size(64)>>} -> {:ok, signature}
      {:ok, <<13, 115, 101, 19, 63, signature::binary-size(64)>>} -> {:ok, signature}
      {:ok, <<54, 240, 44, 52, signature::binary-size(64)>>} -> {:ok, signature}
      {:ok, <<4, 130, 43, signature::binary-size(64)>>} -> {:ok, signature}
      {:ok, <<40, 171, 64, 207, signature::binary-size(96)>>} -> {:ok, signature}
      _ -> :error
    end
  end

  @spec chain_id(String.t()) :: {:ok, binary()} | :error
  def chain_id(value) do
    case payload(value) do
      {:ok, <<87, 82, 0, chain_id::binary-size(4)>>} -> {:ok, chain_id}
      _ -> :error
    end
  end

  # An empty entrypoint means default, and an explicit `%default` is forbidden
  # (entrypoint_repr.ml, `of_string_strict`). Names are at most 31 bytes.
  defp split_entrypoint(value) do
    case String.split(value, "%", parts: 2) do
      [address] -> {:ok, address, "default"}
      [address, ""] -> {:ok, address, "default"}
      [_address, "default"] -> :error
      [address, entrypoint] when byte_size(entrypoint) <= 31 -> {:ok, address, entrypoint}
      _ -> :error
    end
  end

  defp destination(<<2, 90, 121, hash::binary-size(20)>>) do
    {:ok, <<1, hash::binary, 0>>}
  end

  defp destination(<<6, 124, 117, hash::binary-size(20)>>) do
    {:ok, <<3, hash::binary, 0>>}
  end

  defp destination(<<1, 23, 224, 125, hash::binary-size(20)>>) do
    {:ok, <<4, hash::binary, 0>>}
  end

  defp destination(payload) do
    with {:ok, key_hash} <- implicit(payload) do
      {:ok, <<0, key_hash::binary>>}
    end
  end

  defp implicit(<<6, 161, 159, hash::binary-size(20)>>), do: {:ok, <<0, hash::binary>>}
  defp implicit(<<6, 161, 161, hash::binary-size(20)>>), do: {:ok, <<1, hash::binary>>}
  defp implicit(<<6, 161, 164, hash::binary-size(20)>>), do: {:ok, <<2, hash::binary>>}
  defp implicit(<<6, 161, 166, hash::binary-size(20)>>), do: {:ok, <<3, hash::binary>>}
  defp implicit(_payload), do: :error

  # `Base58Check.decode58/1` leaves the 4 checksum bytes on and doesn't check them.
  defp payload(value) do
    case Base58Check.decode58(value) do
      {:ok, raw} when byte_size(raw) > 4 -> verify_checksum(raw)
      _ -> :error
    end
  end

  defp verify_checksum(raw) do
    size = byte_size(raw) - 4
    <<payload::binary-size(^size), checksum::binary-size(4)>> = raw

    case :crypto.hash(:sha256, :crypto.hash(:sha256, payload)) do
      <<^checksum::binary-size(4), _::binary>> -> {:ok, payload}
      _ -> :error
    end
  end
end
