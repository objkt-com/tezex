defmodule Tezex.Micheline do
  @moduledoc """
  Serialize/deserialize data to/from Tezos Micheline optimized binary representation.
  """
  alias Tezex.Forge
  alias Tezex.Zarith

  @type pack_types :: nil | :address | :bytes | :int | :key_hash | :nat | :string

  @doc """
  Serialize a piece of data to its optimized binary representation.

  ## Examples
      iex> Micheline.pack(-6407, :int)
      "0500c764"
      iex> Micheline.pack(%{"prim" => "Pair", "args" => [%{"int" => "-33"}, %{"int" => "71"}]})
      "0507070061008701"
  """
  @spec pack(binary() | integer() | map(), pack_types()) :: nonempty_binary()
  @spec pack(binary() | integer() | map()) :: nonempty_binary()
  def pack(value, type \\ nil) do
    case type do
      :int ->
        "0500" <> Zarith.encode(value)

      :nat ->
        "0500" <> Zarith.encode(value)

      :string ->
        hex_bytes = :binary.encode_hex(value, :lowercase)
        "0501" <> encode_byte_size(hex_bytes) <> hex_bytes

      :bytes ->
        hex_bytes = :binary.encode_hex(value, :lowercase)
        "050a#{encode_byte_size(hex_bytes)}#{hex_bytes}"

      :key_hash ->
        address = Forge.forge_address(value, :hex)
        "050a#{encode_byte_size(address)}#{address}"

      :address ->
        address = Forge.forge_address(value, :hex)
        "050a#{encode_byte_size(address)}#{address}"

      nil ->
        "05" <> Forge.forge_micheline(value, :hex)
    end
  end

  @doc """
  Deserialize a piece of data from its optimized binary representation.

  ## Examples
      iex> Micheline.unpack("050a0000001601e67bac124dff100a57644de0cf26d341ebf9492600", :address)
      "KT1VbT8n6YbrzPSjdAscKfJGDDNafB5yHn1H"
      iex> Micheline.unpack("0507070001000c")
      %{"prim" => "Pair", "args" => [%{"int" => "1"}, %{"int" => "12"}]}
  """
  @type unpack_result :: binary() | integer() | map() | list(unpack_result())
  @spec unpack(binary(), pack_types()) :: unpack_result()
  @spec unpack(binary()) :: unpack_result()
  def unpack(hex_value, type \\ nil) do
    case type do
      :int ->
        hex_value
        |> binary_slice(4..-1//1)
        |> Forge.unforge_int(:hex)
        |> elem(0)

      :nat ->
        hex_value
        |> binary_slice(4..-1//1)
        |> Forge.unforge_int(:hex)
        |> elem(0)

      :string ->
        hex_value
        |> binary_slice(12..-1//1)
        |> :binary.decode_hex()

      :bytes ->
        hex_value
        |> binary_slice(12..-1//1)

      :key_hash ->
        ("00" <> binary_slice(hex_value, 12..-1//1))
        |> Forge.unforge_address(:hex)

      :address ->
        hex_value
        |> binary_slice(12..-1//1)
        |> Forge.unforge_address(:hex)

      nil ->
        hex_value
        |> binary_slice(2..-1//1)
        |> Forge.unforge_micheline(:hex)
    end
  end

  defp encode_byte_size(bytes) do
    (byte_size(bytes) / 2)
    |> trunc()
    |> Integer.to_string(16)
    |> String.pad_leading(8, "0")
  end
end
