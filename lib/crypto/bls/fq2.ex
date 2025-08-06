defmodule Tezex.Crypto.BLS.Fq2 do
  @moduledoc """
  Quadratic extension field Fq2 for BLS12-381.

  Fq2 = Fq[u] / (u^2 + 1) where Fq is the base field.
  Elements are represented as a + b*u where a, b ∈ Fq.
  """

  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.Math

  @type t :: {Fq.t(), Fq.t()}

  @zero Fq.zero()
  @one Fq.one()
  @modulus Fq.modulus()

  @doc """
  Creates an Fq2 element from two Fq elements (a + b*u).
  """
  @spec new(Fq.t(), Fq.t()) :: t()
  def new(a, b) when byte_size(a) == 48 and byte_size(b) == 48 do
    {a, b}
  end

  @doc """
  Zero element of Fq2.
  """
  @spec zero() :: t()
  def zero do
    {@zero, @zero}
  end

  @doc """
  One element of Fq2.
  """
  @spec one() :: t()
  def one do
    {@one, @zero}
  end

  @doc """
  Checks if an Fq2 element is zero.
  """
  @spec is_zero?(t()) :: boolean()
  def is_zero?({a, b}) do
    Fq.is_zero?(a) and Fq.is_zero?(b)
  end

  @doc """
  Checks if an Fq2 element is one.
  """
  @spec is_one?(t()) :: boolean()
  def is_one?({a, b}) do
    Fq.is_one?(a) and Fq.is_zero?(b)
  end

  @doc """
  Adds two Fq2 elements.
  """
  @spec add(t(), t()) :: t()
  def add({a1, b1}, {a2, b2}) do
    {Fq.add(a1, a2), Fq.add(b1, b2)}
  end

  @doc """
  Subtracts two Fq2 elements (x - y).
  """
  @spec sub(t(), t()) :: t()
  def sub({a1, b1}, {a2, b2}) do
    {Fq.sub(a1, a2), Fq.sub(b1, b2)}
  end

  @doc """
  Multiplies two Fq2 elements.
  (a1 + b1*u) * (a2 + b2*u) = (a1*a2 - b1*b2) + (a1*b2 + b1*a2)*u
  """
  @spec mul(t(), t()) :: t()
  def mul({a1, b1}, {a2, b2}) do
    # (a1 + b1*u) * (a2 + b2*u) = a1*a2 + a1*b2*u + b1*a2*u + b1*b2*u^2
    # Since u^2 = -1, this becomes: (a1*a2 - b1*b2) + (a1*b2 + b1*a2)*u
    a1_a2 = Fq.mul(a1, a2)
    b1_b2 = Fq.mul(b1, b2)
    a1_b2 = Fq.mul(a1, b2)
    b1_a2 = Fq.mul(b1, a2)

    real_part = Fq.sub(a1_a2, b1_b2)
    imag_part = Fq.add(a1_b2, b1_a2)

    {real_part, imag_part}
  end

  @doc """
  Negates an Fq2 element.
  """
  @spec neg(t()) :: t()
  def neg({a, b}) do
    {Fq.neg(a), Fq.neg(b)}
  end

  @doc """
  Squares an Fq2 element.
  (a + b*u)^2 = a^2 + 2*a*b*u + b^2*u^2 = (a^2 - b^2) + (2*a*b)*u
  """
  @spec square(t()) :: t()
  def square({a, b}) do
    a_squared = Fq.square(a)
    b_squared = Fq.square(b)
    ab = Fq.mul(a, b)
    two_ab = Fq.add(ab, ab)

    real_part = Fq.sub(a_squared, b_squared)
    imag_part = two_ab

    {real_part, imag_part}
  end

  @doc """
  Computes the conjugate of an Fq2 element.
  conj(a + b*u) = a - b*u
  """
  @spec conjugate(t()) :: t()
  def conjugate({a, b}) do
    {a, Fq.neg(b)}
  end

  @doc """
  Computes the norm of an Fq2 element.
  norm(a + b*u) = (a + b*u) * (a - b*u) = a^2 + b^2
  """
  @spec norm(t()) :: Fq.t()
  def norm({a, b}) do
    a_squared = Fq.square(a)
    b_squared = Fq.square(b)
    Fq.add(a_squared, b_squared)
  end

  @doc """
  Computes the modular inverse of an Fq2 element.
  inv(a + b*u) = conj(a + b*u) / norm(a + b*u)
  """
  @spec inv(t()) :: {:ok, t()} | {:error, :not_invertible}
  def inv(element) do
    if is_zero?(element) do
      {:error, :not_invertible}
    else
      case Fq.inv(norm(element)) do
        {:ok, norm_inv} ->
          conj = conjugate(element)
          {conj_a, conj_b} = conj
          result_a = Fq.mul(conj_a, norm_inv)
          result_b = Fq.mul(conj_b, norm_inv)
          {:ok, {result_a, result_b}}

        {:error, _} ->
          {:error, :not_invertible}
      end
    end
  end

  @doc """
  Raises an Fq2 element to a power.
  """
  @spec pow(t(), non_neg_integer()) :: t()
  def pow(base, exp) when is_integer(exp) and exp >= 0 do
    Math.binary_pow(base, exp, one(), &mul/2)
  end

  @doc """
  Checks if two Fq2 elements are equal.
  """
  @spec eq?(t(), t()) :: boolean()
  def eq?({a1, b1}, {a2, b2}) do
    Fq.eq?(a1, a2) and Fq.eq?(b1, b2)
  end

  @doc """
  Creates an Fq2 element from integers.
  """
  @spec from_integers(non_neg_integer(), non_neg_integer()) :: t()
  def from_integers(a_int, b_int) do
    a = Fq.from_integer(a_int)
    b = Fq.from_integer(b_int)
    {a, b}
  end

  @doc """
  Extracts the coefficients of an Fq2 element as a tuple of integers.
  """
  @spec to_integers(t()) :: {non_neg_integer(), non_neg_integer()}
  def to_integers({a, b}) do
    {Fq.to_integer(a), Fq.to_integer(b)}
  end

  @doc """
  Returns the field modulus.
  """
  @spec modulus() :: non_neg_integer()
  def modulus do
    @modulus
  end

  @doc """
  Multiplies an Fq2 element by a scalar.
  """
  @spec mul_scalar(t(), non_neg_integer()) :: t()
  def mul_scalar({a, b}, scalar) do
    scalar_fq = Fq.from_integer(scalar)
    {Fq.mul(a, scalar_fq), Fq.mul(b, scalar_fq)}
  end

  @doc """
  Computes the square root of an Fq2 element using modular square root algorithm.
  """
  @spec sqrt(t()) :: {:ok, t()} | {:error, :no_sqrt}
  def sqrt(element) do
    cond do
      is_zero?(element) ->
        {:ok, zero()}

      eq?(element, one()) ->
        {:ok, one()}

      true ->
        modular_squareroot_in_fq2(element)
    end
  end

  # Modular square root algorithm for Fq2
  # FQ2_ORDER constant
  @fq2_order 16_019_282_247_729_705_411_943_748_644_318_972_617_695_120_099_330_552_659_862_384_536_985_976_748_491_357_143_400_656_079_302_193_429_974_954_385_540_170_730_531_103_884_539_706_905_936_200_202_421_036_435_811_093_013_034_271_812_758_016_407_969_496_331_661_418_541_023_677_774_899_971_425_993_489_485_368

  # EIGHTH_ROOTS_OF_UNITY - need both the check roots and the divisor roots
  @eighth_roots_check [
    # index 0: (1, 0)
    {Fq.from_integer(1), Fq.from_integer(0)},
    # index 2: (0, 1)
    {Fq.from_integer(0), Fq.from_integer(1)},
    # index 4: (-1, 0)
    {Fq.from_integer(
       4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_786
     ), Fq.from_integer(0)},
    # index 6: (0, -1)
    {Fq.from_integer(0),
     Fq.from_integer(
       4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_786
     )}
  ]

  # EIGHTH_ROOTS_OF_UNITY divisors (for indices 0, 1, 2, 3)
  @eighth_roots_divisors [
    # index 0: (1, 0)
    {Fq.from_integer(1), Fq.from_integer(0)},
    # index 1
    {Fq.from_integer(
       1_028_732_146_235_106_349_975_324_479_215_795_277_384_839_936_929_757_896_155_643_118_032_610_843_298_655_225_875_571_310_552_543_014_690_878_354_869_257
     ),
     Fq.from_integer(
       2_973_677_408_986_561_043_442_465_346_520_108_879_172_042_883_009_249_989_176_415_018_091_420_807_192_182_638_567_116_318_576_472_649_347_015_917_690_530
     )},
    # index 2: (0, 1)
    {Fq.from_integer(0), Fq.from_integer(1)},
    # index 3
    {Fq.from_integer(
       1_028_732_146_235_106_349_975_324_479_215_795_277_384_839_936_929_757_896_155_643_118_032_610_843_298_655_225_875_571_310_552_543_014_690_878_354_869_257
     ),
     Fq.from_integer(
       1_028_732_146_235_106_349_975_324_479_215_795_277_384_839_936_929_757_896_155_643_118_032_610_843_298_655_225_875_571_310_552_543_014_690_878_354_869_257
     )}
  ]

  defp modular_squareroot_in_fq2(value) do
    # candidate_squareroot = value ** ((FQ2_ORDER + 8) // 16)
    exponent = div(@fq2_order + 8, 16)
    candidate_squareroot = pow(value, exponent)

    # check = candidate_squareroot**2 / value
    candidate_squared = square(candidate_squareroot)

    case inv(value) do
      {:ok, value_inv} ->
        check = mul(candidate_squared, value_inv)

        # if check in EIGHTH_ROOTS_OF_UNITY[::2]:
        if check_eighth_root(check) do
          # Find which eighth root it is and compute the result
          compute_sqrt_result(candidate_squareroot, check)
        else
          {:error, :no_sqrt}
        end

      {:error, _} ->
        {:error, :no_sqrt}
    end
  end

  defp check_eighth_root(check) do
    # Check if check is in any of our check eighth roots (every other one)
    Enum.any?(@eighth_roots_check, fn root -> eq?(check, root) end)
  end

  defp compute_sqrt_result(candidate_squareroot, check) do
    # Find which eighth root it matches and get its index
    check_index = Enum.find_index(@eighth_roots_check, fn root -> eq?(check, root) end) || 0

    # Map check indices to original indices: 0->0, 1->2, 2->4, 3->6
    original_index = check_index * 2

    # x1 = candidate_squareroot / EIGHTH_ROOTS_OF_UNITY[original_index // 2]
    # 0->0, 2->1, 4->2, 6->3
    divisor_index = div(original_index, 2)
    divisor = Enum.at(@eighth_roots_divisors, divisor_index)

    case inv(divisor) do
      {:ok, divisor_inv} ->
        x1 = mul(candidate_squareroot, divisor_inv)
        x2 = neg(x1)

        # Return x1 if (x1_im > x2_im or (x1_im == x2_im and x1_re > x2_re)) else x2
        {x1_re, x1_im} = x1
        {x2_re, x2_im} = x2

        x1_re_int = Fq.to_integer(x1_re)
        x1_im_int = Fq.to_integer(x1_im)
        x2_re_int = Fq.to_integer(x2_re)
        x2_im_int = Fq.to_integer(x2_im)

        result =
          if x1_im_int > x2_im_int or (x1_im_int == x2_im_int and x1_re_int > x2_re_int) do
            x1
          else
            x2
          end

        {:ok, result}

      {:error, _} ->
        {:error, :no_sqrt}
    end
  end

  @doc """
  Sign function sgn0(x) = 1 when x is 'negative'; otherwise, sgn0(x) = 0.
  For Fq2, this is optimized for m = 2 as defined in the hash-to-curve spec.
  """
  @spec sgn0(t()) :: 0 | 1
  def sgn0({a, b}) do
    a_int = :binary.decode_unsigned(a)
    b_int = :binary.decode_unsigned(b)

    sign_0 = rem(a_int, 2)
    zero_0 = if a_int == 0, do: 1, else: 0
    sign_1 = rem(b_int, 2)

    # sign_0 OR (zero_0 AND sign_1)
    case {sign_0, zero_0, sign_1} do
      {1, _, _} -> 1
      {0, 1, 1} -> 1
      _ -> 0
    end
  end
end
