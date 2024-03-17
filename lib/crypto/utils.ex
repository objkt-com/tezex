# Copied and modified from <https://github.com/starkbank/ecdsa-elixir>, Copyright (c) 2020 Stark Bank S.A, MIT License.
defmodule Tezex.Crypto.Utils do
  @moduledoc false
  import Bitwise

  @spec mod(integer, integer) :: non_neg_integer
  def mod(x, n) do
    case rem(x, n) do
      r when r < 0 -> r + n
      r -> r
    end
  end

  @spec mod_add(integer, integer, integer) :: non_neg_integer
  def mod_add(left, right, modulus) do
    mod(left + right, modulus)
  end

  @spec mod_sub(integer, integer, integer) :: non_neg_integer
  def mod_sub(left, right, modulus) do
    mod(left - right, modulus)
  end

  def ipow(base, p, acc \\ 1)

  def ipow(base, p, acc) when p > 0 do
    ipow(base, p - 1, base * acc)
  end

  def ipow(_base, _p, acc) do
    acc
  end

  @spec number_from_string(binary) :: integer
  def number_from_string(string) do
    {parsed_int, ""} =
      string
      |> Base.encode16()
      |> Integer.parse(16)

    parsed_int
  end

  @spec string_from_number(integer(), non_neg_integer()) :: binary()
  def string_from_number(number, string_length) do
    number
    |> Integer.to_string(16)
    |> fill_number_string(string_length)
    |> Base.decode16!()
  end

  defp fill_number_string(string, string_length) do
    String.duplicate("0", 2 * string_length - byte_size(string)) <> string
  end

  def rand_fun(bytes_needed) do
    :crypto.strong_rand_bytes(bytes_needed)
  end

  @spec between(number(), number()) :: number()
  def between(minimum, maximum) when minimum < maximum do
    range = maximum - minimum + 1
    {bytes_needed, mask} = calculate_parameters(range)

    # We apply the mask to reduce the amount of attempts we might need
    # to make to get a number that is in range. This is somewhat like
    # the commonly used 'modulo trick', but without the bias:
    #
    # > Let's say you invoke secure_rand(0, 60). When the other code
    # > generates a random integer, you might get 243. If you take
    # > (243 & 63)-- noting that the mask is 63-- you get 51. Since
    # > 51 is less than 60, we can return this without bias. If we
    # > got 255, then 255 & 63 is 63. 63 > 60, so we try again.
    #
    # > The purpose of the mask is to reduce the number of random
    # > numbers discarded for the sake of ensuring an unbiased
    # > distribution. In the example above, 243 would discard, but
    # > (243 & 63) is in the range of 0 and 60.
    #
    # (Source: Scott Arciszewski)

    random_number =
      rand_fun(bytes_needed)
      |> :binary.bin_to_list()
      |> bytes_to_number &&& mask

    if random_number < range do
      minimum + random_number
    else
      # Outside of the acceptable range, throw it away and try again.
      # We don't try any modulo tricks, as this would introduce bias.
      between(minimum, maximum)
    end
  end

  defp bytes_to_number(random_bytes, random_number \\ 0, i \\ 0)

  defp bytes_to_number([random_byte | other_random_bytes], random_number, i) do
    bytes_to_number(
      other_random_bytes,
      random_number ||| random_byte <<< (8 * i),
      i + 1
    )
  end

  defp bytes_to_number([], random_number, _i) do
    random_number
  end

  defp calculate_parameters(range) do
    calculate_parameters(range, 1, 0)
  end

  defp calculate_parameters(range, mask, bits_needed) when range > 0 do
    calculate_parameters(
      range >>> 1,
      mask <<< 1 ||| 1,
      bits_needed + 1
    )
  end

  defp calculate_parameters(_range, mask, bits_needed) do
    {div(bits_needed, 8) + 1, mask}
  end

  @spec pad(binary(), integer(), :leading | :trailing) :: binary()
  def pad(bin, byte_length, type) when is_binary(bin) do
    cond do
      byte_size(bin) == byte_length ->
        bin

      type == :leading ->
        pad_len = 8 * byte_length - byte_size(bin) * 8
        <<0::size(pad_len)>> <> bin

      type == :trailing ->
        pad_len = 8 * byte_length - byte_size(bin) * 8
        bin <> <<0::size(pad_len)>>
    end
  end

  def truncate_to_n(msg, n, trunc_only \\ false) do
    delta =
      byte_size(:binary.encode_unsigned(msg)) * 8 - byte_size(:binary.encode_unsigned(n)) * 8

    msg =
      if delta > 0 do
        msg >>> delta
      else
        msg
      end

    if not trunc_only and msg >= n do
      msg - n
    else
      msg
    end
  end
end
