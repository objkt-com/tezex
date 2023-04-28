defmodule Tezex.Crypto.Utils do
  @moduledoc false

  def mod(x, n) do
    case rem(x, n) do
      r when r < 0 -> r + n
      r -> r
    end
  end

  def mod_add(left, right, modulus) do
    mod(left + right, modulus)
  end

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

  def number_from_string(string) do
    {parsed_int, ""} =
      string
      |> Base.encode16()
      |> Integer.parse(16)

    parsed_int
  end
end
