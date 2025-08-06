defmodule Tezex.Crypto.BLS.Fr do
  @moduledoc """
  Scalar field Fr for BLS12-381 (curve order).

  This is the field of scalars used for private keys and in elliptic curve operations.
  """

  alias Tezex.Crypto.BLS.Constants

  # BLS12-381 scalar field order (r)
  @order Constants.curve_order()

  @type t :: binary()

  @doc """
  Creates a field element from an integer.
  """
  @spec from_integer(non_neg_integer()) :: t()
  def from_integer(n) when is_integer(n) and n >= 0 do
    # Reduce modulo the field order and convert to 32-byte big-endian
    reduced = rem(n, @order)
    <<reduced::big-unsigned-integer-size(256)>>
  end

  @doc """
  Creates a field element from a binary (32 bytes, big-endian).
  """
  @spec from_bytes(binary()) :: {:ok, t()} | {:error, :invalid_size}
  def from_bytes(bytes) when byte_size(bytes) == 32 do
    <<value::big-unsigned-integer-size(256)>> = bytes

    if value < @order do
      {:ok, bytes}
    else
      # Reduce if needed
      {:ok, from_integer(value)}
    end
  end

  def from_bytes(_), do: {:error, :invalid_size}

  @doc """
  Converts a field element to integer.
  """
  @spec to_integer(t()) :: non_neg_integer()
  def to_integer(fr) when byte_size(fr) == 32 do
    <<value::big-unsigned-integer-size(256)>> = fr
    value
  end

  @doc """
  Converts a field element to 32-byte big-endian binary.
  """
  @spec to_bytes(t()) :: binary()
  def to_bytes(fr) when byte_size(fr) == 32 do
    fr
  end

  @doc """
  Zero element of the field.
  """
  @spec zero() :: t()
  def zero do
    <<0::big-unsigned-integer-size(256)>>
  end

  @doc """
  One element of the field.
  """
  @spec one() :: t()
  def one do
    <<1::big-unsigned-integer-size(256)>>
  end

  @doc """
  Checks if a field element is zero.
  """
  @spec is_zero?(t()) :: boolean()
  def is_zero?(fr) do
    fr == zero()
  end
end
