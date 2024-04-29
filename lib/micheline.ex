defmodule Tezex.Micheline do
  alias Tezex.Forge
  alias Tezex.Zarith

  @typep pack_types :: nil | :address | :bytes | :int | :key_hash | :nat | :string
  @spec pack(binary() | integer() | map(), pack_types()) :: nonempty_binary()
  @spec pack(binary() | integer() | map()) :: nonempty_binary()
  @doc """
  Serialize a piece of data to its optimized binary representation.

  ## Examples
      iex> Micheline.pack(-6407, :int)
      "0500c764"
      iex> Micheline.pack(%{"prim" => "Pair", "args" => [%{"int" => "-33"}, %{"int" => "71"}]})
      "0507070061008701"
  """
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
        address = :binary.encode_hex(Forge.forge_address(value), :lowercase)
        "050a#{encode_byte_size(address)}#{address}"

      :address ->
        address = :binary.encode_hex(Forge.forge_address(value), :lowercase)
        "050a#{encode_byte_size(address)}#{address}"

      nil ->
        "05" <> :binary.encode_hex(Forge.forge_micheline(value), :lowercase)
    end
  end

  @spec unpack(binary(), pack_types()) :: binary() | integer() | map()
  @spec unpack(binary()) :: binary() | integer() | map()
  @doc """
  Deserialize a piece of data from its optimized binary representation.

  ## Examples
      iex> Micheline.unpack("050a0000001601e67bac124dff100a57644de0cf26d341ebf9492600", :address)
      "KT1VbT8n6YbrzPSjdAscKfJGDDNafB5yHn1H"
      iex> Micheline.unpack("0507070001000c")
      %{"prim" => "Pair", "args" => [%{"int" => "1"}, %{"int" => "12"}]}
  """
  def unpack(hex_value, type \\ nil) do
    case type do
      :int ->
        hex_value
        |> binary_slice(4..-1//1)
        |> :binary.decode_hex()
        |> Forge.unforge_int()
        |> elem(0)

      :nat ->
        hex_value
        |> binary_slice(4..-1//1)
        |> :binary.decode_hex()
        |> Forge.unforge_int()
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
        |> :binary.decode_hex()
        |> Forge.unforge_address()

      :address ->
        hex_value
        |> binary_slice(12..-1//1)
        |> :binary.decode_hex()
        |> Forge.unforge_address()

      nil ->
        hex_value
        |> binary_slice(2..-1//1)
        |> :binary.decode_hex()
        |> Forge.unforge_micheline()
    end
  end

  defp encode_byte_size(bytes) do
    (byte_size(bytes) / 2)
    |> trunc()
    |> Integer.to_string(16)
    |> String.pad_leading(8, "0")
  end
end
