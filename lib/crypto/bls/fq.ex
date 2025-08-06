defmodule Tezex.Crypto.BLS.Fq do
  @moduledoc """
  Base field Fq for BLS12-381.

  This is the base field over which the BLS12-381 elliptic curves are defined.
  Modulus: 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
  """

  alias Tezex.Crypto.Math
  alias Tezex.Crypto.BLS.Constants

  @type t :: binary()

  # BLS12-381 base field modulus (q)
  @modulus Constants.field_modulus()
  @zero <<0::big-unsigned-integer-size(384)>>
  @one <<1::big-unsigned-integer-size(384)>>

  @doc """
  Returns the field modulus.
  """
  @spec modulus() :: non_neg_integer()
  def modulus, do: @modulus

  @doc """
  Creates a field element from an integer.
  Negative integers are converted to their positive modular equivalent.
  """
  @spec from_integer(integer()) :: t()
  def from_integer(n) when is_integer(n) do
    # Handle negative integers by converting to positive modular equivalent
    reduced =
      if n >= 0 do
        rem(n, @modulus)
      else
        # For negative n, compute n mod p as (p - ((-n) mod p)) mod p
        @modulus - rem(-n, @modulus)
      end

    <<reduced::big-unsigned-integer-size(384)>>
  end

  @doc """
  Creates a field element from a binary (48 bytes, big-endian).
  """
  @spec from_bytes(binary()) :: {:ok, t()} | {:error, :invalid_size}
  def from_bytes(<<value::big-unsigned-integer-size(384)>> = bytes) do
    if value < @modulus do
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
  def to_integer(<<value::big-unsigned-integer-size(384)>>) do
    value
  end

  @doc """
  Converts a field element to 48-byte big-endian binary.
  """
  @spec to_bytes(t()) :: binary()
  def to_bytes(fq) when byte_size(fq) == 48 do
    fq
  end

  @doc """
  Zero element of the field.
  """
  @spec zero :: t()
  def zero, do: @zero

  @doc """
  One element of the field.
  """
  @spec one :: t()
  def one, do: @one

  @doc """
  Checks if a field element is zero.
  """
  @spec is_zero?(t()) :: boolean()
  def is_zero?(fq) do
    fq == @zero
  end

  @doc """
  Checks if a field element is one.
  """
  @spec is_one?(t()) :: boolean()
  def is_one?(fq) do
    fq == @one
  end

  @doc """
  Adds two field elements.
  """
  @spec add(t(), t()) :: t()
  def add(a, b) when byte_size(a) == 48 and byte_size(b) == 48 do
    a_int = to_integer(a)
    b_int = to_integer(b)
    result = rem(a_int + b_int, @modulus)
    from_integer(result)
  end

  @doc """
  Subtracts two field elements (a - b).
  """
  @spec sub(t(), t()) :: t()
  def sub(a, b) when byte_size(a) == 48 and byte_size(b) == 48 do
    a_int = to_integer(a)
    b_int = to_integer(b)
    result = rem(a_int - b_int + @modulus, @modulus)
    from_integer(result)
  end

  @doc """
  Multiplies two field elements.
  """
  @spec mul(t(), t()) :: t()
  def mul(a, b) when byte_size(a) == 48 and byte_size(b) == 48 do
    a_int = to_integer(a)
    b_int = to_integer(b)
    result = rem(a_int * b_int, @modulus)
    from_integer(result)
  end

  @doc """
  Negates a field element.
  """
  @spec neg(t()) :: t()
  def neg(a) when byte_size(a) == 48 do
    if is_zero?(a) do
      @zero
    else
      a_int = to_integer(a)
      result = rem(@modulus - a_int, @modulus)
      from_integer(result)
    end
  end

  @doc """
  Squares a field element.
  """
  @spec square(t()) :: t()
  def square(a) when byte_size(a) == 48 do
    mul(a, a)
  end

  @doc """
  Computes the modular inverse of a field element.
  Returns {:ok, inverse} or {:error, :not_invertible} if the element is zero.
  """
  @spec inv(t()) :: {:ok, t()} | {:error, :not_invertible}
  def inv(a) when byte_size(a) == 48 do
    with false <- is_zero?(a),
         a_int = to_integer(a),
         {:ok, inv_int} <- Math.mod_inverse(a_int, @modulus) do
      {:ok, from_integer(inv_int)}
    else
      _ -> {:error, :not_invertible}
    end
  end

  @doc """
  Raises a field element to a power.
  """
  @spec pow(t(), non_neg_integer()) :: t()
  def pow(base, exp) when byte_size(base) == 48 and is_integer(exp) and exp >= 0 do
    base
    |> to_integer()
    |> Math.mod_pow(exp, @modulus)
    |> from_integer()
  end

  @doc """
  Checks if two field elements are equal.
  """
  @spec eq?(t(), t()) :: boolean()
  def eq?(a, a) when byte_size(a) == 48, do: true
  def eq?(_, _), do: false

  @doc """
  Computes the square root of a field element if it exists.
  """
  @spec sqrt(t()) :: {:ok, t()} | {:error, :no_sqrt}
  def sqrt(a) when byte_size(a) == 48 do
    # Use Tonelli-Shanks algorithm for square root
    # Since q ≡ 3 (mod 4), we can use a^((q+1)/4)
    with false <- is_zero?(a) and :is_zero,
         3 <- rem(@modulus, 4),
         exp = div(@modulus + 1, 4),
         candidate = pow(a, exp),
         # Verify it's actually a square root
         true <- eq?(square(candidate), a) do
      {:ok, candidate}
    else
      :is_zero -> {:ok, @zero}
      _ -> {:error, :no_sqrt}
    end
  end

  @doc """
  Generates a random field element.
  """
  @spec random() :: t()
  def random do
    # Generate 48 random bytes and reduce modulo the field modulus
    random_bytes = :crypto.strong_rand_bytes(48)
    <<random_int::big-unsigned-integer-size(384)>> = random_bytes
    from_integer(random_int)
  end

  @doc """
  Computes the Frobenius endomorphism φ: Fq → Fq where φ(x) = x^p.
  For the base field Fq, this is the identity function since x^p ≡ x (mod p).
  """
  @spec frobenius(t()) :: t()
  def frobenius(a) when byte_size(a) == 48 do
    a
  end
end
