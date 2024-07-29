defmodule Tezex.Zarith do
  @moduledoc """
  Provides encoding and decoding functions for Zarith numbers.

  A Zarith number is an integer encoded as a variable length sequence of bytes.

  Each byte has a running unary size bit:
    - The most significant bit of each byte tells if this is the last byte in the sequence (0) or if there is more to read (1)
    - The second most significant bit of the first byte is reserved for the sign (positive if zero)

  Size and sign bits ignored, data is then the binary representation of the absolute value of the number in little endian order.
  """

  @typedoc """
  Represents a Zarith-encoded integer as a hexadecimal string.
  """
  @type zarith_hex :: String.t()

  @typedoc """
  Represents a decoded Zarith number as an Elixir integer.
  """
  @type decoded_zarith :: integer()

  @doc """
  Decodes a Zarith-encoded integer.

  Takes a hexadecimal string representation of a Zarith-encoded number and returns the integer in base 10.

  ## Parameters

    * `binary_input` - A hexadecimal string representing the Zarith-encoded integer.

  ## Returns

    The decoded integer.

  ## Examples

      iex> Tezex.Zarith.decode("a1d22c")
      365_729

      iex> Tezex.Zarith.decode("e1d22c")
      -365_729

  """
  @spec decode(zarith_hex()) :: decoded_zarith()
  def decode(binary_input) when is_binary(binary_input) do
    {%{int: integer}, _} = consume(binary_input)
    String.to_integer(integer)
  end

  @doc """
  Encodes an integer to a Zarith-encoded hexadecimal string.

  Takes an integer in base 10 and returns the Zarith-encoded hexadecimal string.

  Implementation based on [anchorageoss/tezosprotocol (MIT License - Copyright (c) 2019 Anchor Labs, Inc.)](https://github.com/anchorageoss/tezosprotocol/blob/23a051d34fcfda8393940141f8151113a1aca10b/zarith/zarith.go#L153)

  ## Parameters

    * `integer` - The integer to be encoded.

  ## Returns

    A hexadecimal string representing the Zarith-encoded integer.

  ## Examples

      iex> Tezex.Zarith.encode(365_729)
      "a1d22c"

      iex> Tezex.Zarith.encode(-365_729)
      "e1d22c"

  """
  @spec encode(decoded_zarith()) :: zarith_hex()
  def encode(integer) when is_integer(integer) do
    sign = if integer < 0, do: 1, else: 0

    bin = :binary.encode_unsigned(abs(integer), :big)

    value_bits =
      for <<part::size(1) <- bin>> do
        part
      end
      |> Enum.drop_while(&(&1 == 0))

    num_value_bits = length(value_bits)
    length_zarith_bit_segment = 7
    length_zarith_bit_segment_with_sign_flag = length_zarith_bit_segment - 1

    encoding_fits_in_one_byte = num_value_bits <= length_zarith_bit_segment_with_sign_flag

    num_padding_bits_required =
      if encoding_fits_in_one_byte do
        length_zarith_bit_segment_with_sign_flag - num_value_bits
      else
        num_bits_after_first_segment = num_value_bits - length_zarith_bit_segment_with_sign_flag

        if rem(num_bits_after_first_segment, length_zarith_bit_segment) == 0 do
          0
        else
          length_zarith_bit_segment - rem(num_bits_after_first_segment, length_zarith_bit_segment)
        end
      end

    padded_bit_string_buffer = Stream.cycle([0]) |> Enum.take(num_padding_bits_required)

    padded_bit_string = padded_bit_string_buffer ++ value_bits

    # First segment is the rightmost 6 bits of the input value, prefixed with the sign bit
    {first_segment, _rest} = Enum.split(Enum.reverse(padded_bit_string), 6)
    first_segment = Enum.reverse(first_segment)
    first_segment = [sign | first_segment]

    padded_bit_string =
      Enum.take(padded_bit_string, length(padded_bit_string) - 6)
      |> Enum.chunk_every(7)
      |> Enum.reverse()

    segments =
      [first_segment | padded_bit_string]
      |> continues()

    bits_count = length(segments)

    <<integer::integer-size(bits_count)>> = Enum.into(segments, <<>>, fn bit -> <<bit::1>> end)

    dec_to_hex(integer)
  end

  defp continues([x | []]) do
    [0 | x]
  end

  defp continues([x | rest]) do
    [1 | x] ++ continues(rest)
  end

  @doc """
  Consumes a Zarith-encoded integer.

  Takes a hexadecimal string and returns the decoded integer in base 10 along with how many characters of the input string
  were used to decode the integer.

  ## Parameters

    * `binary_input` - A hexadecimal string representing the Zarith-encoded integer.

  ## Returns

    A tuple containing:
    - A map with the key `:int` and the decoded integer as a string value.
    - The number of characters consumed from the input string.

  ## Examples

      iex> Tezex.Zarith.consume("a1d22c")
      {%{int: "365729"}, 6}

      iex> Tezex.Zarith.consume("e1d22c")
      {%{int: "-365729"}, 6}

  """
  @spec consume(zarith_hex()) :: {%{int: String.t()}, pos_integer()}
  def consume(binary_input) when is_binary(binary_input) do
    {carved_int, rest} = find_int(binary_input)

    consumed = String.length(binary_input) - String.length(rest)

    binary =
      carved_int
      |> hex_to_dec()
      |> :binary.encode_unsigned()

    integer =
      for <<byte::binary-size(1) <- binary>> do
        byte
      end
      |> read()

    {integer, consumed}
  end

  defp find_int(_bin, _acc \\ [])

  defp find_int(<<n::bitstring-size(16), rest::bitstring>>, acc) do
    dec = hex_to_dec(n)

    if dec < 128 do
      {Enum.reverse([n | acc]) |> Enum.join(""), rest}
    else
      find_int(rest, [n | acc])
    end
  end

  defp find_int("", acc) do
    {Enum.reverse(acc) |> Enum.join(""), ""}
  end

  defp read([<<_halt::1, sign::1, tail::integer-size(6)>> | rest]) do
    bits =
      for bits_part <- read_next(rest, [<<tail::integer-size(6)>>]), into: <<>> do
        bits_part
      end

    bits_count = bit_size(bits)
    <<integer::integer-size(bits_count)>> = bits

    case sign do
      1 -> %{int: "-#{integer}"}
      0 -> %{int: "#{integer}"}
    end
  end

  defp read_next([<<1::1, tail::integer-size(7)>> | rest], acc) do
    read_next(rest, [<<tail::integer-size(7)>> | acc])
  end

  defp read_next([<<0::1, tail::integer-size(7)>> | _rest], acc) do
    [<<tail::integer-size(7)>> | acc]
  end

  defp read_next(_, acc) do
    acc
  end

  defp hex_to_dec(hex) do
    {d, _} = Integer.parse(hex, 16)
    d
  end

  defp dec_to_hex(dec) do
    Integer.to_string(dec, 16)
    |> String.downcase()
    |> then(fn hex ->
      if rem(byte_size(hex), 2) == 1 do
        "0" <> hex
      else
        hex
      end
    end)
  end
end
