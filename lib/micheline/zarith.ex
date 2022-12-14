defmodule Tezex.Micheline.Zarith do
  @moduledoc """
  A Zarith number is an integer encoded as a variable length sequence of bytes.

  Each byte has a running unary size bit:
    - the most significant bit of each byte tells if this is the last byte in the sequence (0) or if there is more to read (1)
    - the second most significant bit of the first byte is reserved for the sign (positive if zero).

  Size and sign bits ignored, data is then the binary representation of the absolute value of the number in little endian order.
  """

  @doc """
  Decodes a zarith-encoded integer.
  Takes a binary and returns the integer in base 10.

  ## Examples
      iex> Tezex.Micheline.Zarith.decode("00a1d22c")
      365_729

      iex> Tezex.Micheline.Zarith.decode("00e1d22c")
      -365_729
  """
  @spec decode(nonempty_binary) :: integer
  def decode(binary_input) when is_binary(binary_input) do
    {%{int: integer}, _} = consume(binary_input)
    integer
  end

  @doc """
  Encodes an integer to a zarith-encoded binary.
  Takes an integer in base 10 and returns the encoded binary.

  Implementation based on https://github.com/anchorageoss/tezosprotocol/blob/23a051d34fcfda8393940141f8151113a1aca10b/zarith/zarith.go#L153
  MIT License - Copyright (c) 2019 Anchor Labs, Inc.
  """
  @spec encode(integer) :: nonempty_binary
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
  Consumes a zarith-encoded integer.
  Takes a binary and returns the decoded integer in base 10 along with how many characters of the input binary
  were used to decode the integer.
  """
  @spec consume(nonempty_binary) :: {%{int: integer}, pos_integer}
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

  defp find_int(<<n::bitstring-size(16), rest::bitstring>>, acc \\ []) do
    dec = hex_to_dec(n)

    if dec != 0 and dec < 128 do
      {Enum.reverse([n | acc]) |> Enum.join(""), rest}
    else
      find_int(rest, [n | acc])
    end
  end

  defp read([<<_halt::1, sign::1, tail::integer-size(6)>> | rest]) do
    bits =
      for bits_part <- read_next(rest, [<<tail::integer-size(6)>>]), into: <<>> do
        bits_part
      end

    bits_count = bit_size(bits)
    <<integer::integer-size(bits_count)>> = bits

    case sign do
      1 -> %{int: -integer}
      0 -> %{int: integer}
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
  end
end
