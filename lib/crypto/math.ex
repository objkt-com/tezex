# Copied and modified from <https://github.com/starkbank/ecdsa-elixir>, Copyright (c) 2020 Stark Bank S.A, MIT License.
defmodule Tezex.Crypto.Math do
  @moduledoc false

  import Bitwise

  alias Tezex.Crypto.Point
  alias Tezex.Crypto.Utils

  @doc """
  Fast way to multiply point and scalar in elliptic curves

  - `p` [`t:Tezex.Crypto.Point.t/0`]: First Point to multiply
  - `n` [`t:integer/0`]: Scalar to multiply
  - `c_n` [`t:integer/0`]: Order of the elliptic curve
  - `c_p` [`t:integer/0`]: Prime number in the module of the equation Y^2 = X^3 + c_a*X + B (mod p)
  - `c_a` [`t:integer/0`]: Coefficient of the first-order term of the equation Y^2 = X^3 + c_a*X + B (mod p)

  Returns:
  - `point` [`t:Tezex.Crypto.Point.t/0`]: point that represents the sum of First and Second Point
  """
  @spec multiply(Point.t(), integer(), integer(), integer(), integer()) :: Point.t()
  def multiply(p, n, c_n, c_a, c_p) do
    p
    |> to_jacobian()
    |> jacobian_multiply(n, c_n, c_a, c_p)
    |> from_jacobian(c_p)
  end

  @doc """
  Fast way to add two points in elliptic curves

  - `p` [`t:Tezex.Crypto.Point.t/0`]: First Point you want to add
  - `q` [`t:Tezex.Crypto.Point.t/0`]: Second Point you want to add
  - `c_p` [`t:integer/0`]: Prime number in the module of the equation Y^2 = X^3 + c_a*X + B (mod p)
  - `c_a` [`t:integer/0`]: Coefficient of the first-order term of the equation Y^2 = X^3 + c_a*X + B (mod p)

  Returns:
  - `point` [`t:Tezex.Crypto.Point.t/0`]: point that represents the sum of First and Second Point
  """
  @spec add(Point.t(), Point.t(), integer(), integer()) :: Point.t()
  def add(p, q, c_a, c_p) do
    jacobian_add(to_jacobian(p), to_jacobian(q), c_a, c_p)
    |> from_jacobian(c_p)
  end

  @doc """
  Extended Euclidean Algorithm. It's the 'division' in elliptic curves

  - `x` [`t:integer/0`]: Divisor
  - `n` [`t:integer/0`]: Mod for division

  Returns:
  - `value` [`t:integer/0`]: value representing the division
  """
  def inv(x, _n) when x == 0 do
    0
  end

  def inv(x, n) do
    inv_operator(1, 0, Utils.mod(x, n), n)
    |> Utils.mod(n)
  end

  @doc """
  Computes modular inverse using extended Euclidean algorithm.
  Returns {:ok, inverse} or {:error, :not_invertible}.
  """
  @spec mod_inverse(integer(), integer()) :: {:ok, integer()} | {:error, :not_invertible}
  def mod_inverse(a, m) do
    case extended_gcd(a, m) do
      {1, x, _} -> {:ok, rem(x + m, m)}
      _ -> {:error, :not_invertible}
    end
  end

  @doc """
  Extended Euclidean algorithm implementation.
  Returns {gcd, x, y} where gcd = a*x + b*y.
  """
  @spec extended_gcd(integer(), integer()) :: {integer(), integer(), integer()}
  def extended_gcd(a, b) do
    extended_gcd(a, b, 1, 0, 0, 1)
  end

  @doc """
  Fast modular exponentiation.
  """
  @spec mod_pow(integer(), integer(), integer()) :: integer()
  def mod_pow(base, exp, mod) do
    mod_pow(base, exp, mod, 1)
  end

  @doc """
  Generic binary exponentiation using a multiplication function.
  Useful for field elements or other algebraic structures.

  - `base`: The base element
  - `exp`: The exponent (non-negative integer)
  - `one`: The multiplicative identity element
  - `mul_fn`: Function to multiply two elements

  Returns: base^exp
  """
  @spec binary_pow(any(), non_neg_integer(), any(), (any(), any() -> any())) :: any()
  def binary_pow(_base, 0, one, _mul_fn), do: one
  def binary_pow(base, 1, _one, _mul_fn), do: base

  def binary_pow(base, exp, one, mul_fn) when rem(exp, 2) == 0 do
    squared = mul_fn.(base, base)
    binary_pow(squared, div(exp, 2), one, mul_fn)
  end

  def binary_pow(base, exp, one, mul_fn) do
    squared = mul_fn.(base, base)
    half_result = binary_pow(squared, div(exp, 2), one, mul_fn)
    mul_fn.(base, half_result)
  end

  defp inv_operator(lm, hm, low, high) when low > 1 do
    r = div(high, low)

    inv_operator(hm - lm * r, lm, high - low * r, low)
  end

  defp inv_operator(lm, _hm, _low, _high) do
    lm
  end

  defp extended_gcd(0, b, _, _, u1, v1), do: {b, u1, v1}

  defp extended_gcd(a, b, u0, v0, u1, v1) do
    q = div(b, a)
    r = rem(b, a)
    extended_gcd(r, a, u1 - q * u0, v1 - q * v0, u0, v0)
  end

  defp mod_pow(_, 0, _, acc), do: acc

  defp mod_pow(base, exp, mod, acc) do
    if (exp &&& 1) == 1 do
      mod_pow(rem(base * base, mod), exp >>> 1, mod, rem(acc * base, mod))
    else
      mod_pow(rem(base * base, mod), exp >>> 1, mod, acc)
    end
  end

  @doc """
  Converts a point from affine to Jacobian coordinates.

  - `p` [`t:Tezex.Crypto.Point.t/0`]: Point in affine coordinates (z = 0)

  Returns:
  - `point` [`t:Tezex.Crypto.Point.t/0`]: point in Jacobian coordinates (z = 1)
  """
  @spec to_jacobian(Point.t()) :: Point.t()
  def to_jacobian(p) do
    %Point{x: p.x, y: p.y, z: 1}
  end

  @doc """
  Converts a point from Jacobian to affine coordinates.

  - `p` [`t:Tezex.Crypto.Point.t/0`]: Point in Jacobian coordinates
  - `c_p` [`t:integer/0`]: Prime number in the module of the equation Y^2 = X^3 + c_a*X + B (mod p)

  Returns:
  - `point` [`t:Tezex.Crypto.Point.t/0`]: point in affine coordinates (z = 0)
  """
  @spec from_jacobian(Point.t(), integer()) :: Point.t()
  def from_jacobian(p, c_p) do
    z = inv(p.z, c_p)

    %Point{
      x: Utils.mod(p.x * Utils.ipow(z, 2), c_p),
      y: Utils.mod(p.y * Utils.ipow(z, 3), c_p)
    }
  end

  @doc """
  Doubles a point in elliptic curves using Jacobian coordinates.

  - `p` [`t:Tezex.Crypto.Point.t/0`]: Point you want to double (in Jacobian coordinates)
  - `c_a` [`t:integer/0`]: Coefficient of the first-order term of the equation Y^2 = X^3 + c_a*X + B (mod p)
  - `c_p` [`t:integer/0`]: Prime number in the module of the equation Y^2 = X^3 + c_a*X + B (mod p)

  Returns:
  - `point` [`t:Tezex.Crypto.Point.t/0`]: doubled point in Jacobian coordinates
  """
  @spec jacobian_double(Point.t(), integer(), integer()) :: Point.t()
  def jacobian_double(%Point{y: 0}, _c_a, _c_p), do: %Point{x: 0, y: 0, z: 0}

  def jacobian_double(p, c_a, c_p) do
    ysq =
      Utils.ipow(p.y, 2)
      |> Utils.mod(c_p)

    s =
      (4 * p.x * ysq)
      |> Utils.mod(c_p)

    m =
      (3 * Utils.ipow(p.x, 2) + c_a * Utils.ipow(p.z, 4))
      |> Utils.mod(c_p)

    nx =
      (Utils.ipow(m, 2) - 2 * s)
      |> Utils.mod(c_p)

    ny =
      (m * (s - nx) - 8 * Utils.ipow(ysq, 2))
      |> Utils.mod(c_p)

    nz =
      (2 * p.y * p.z)
      |> Utils.mod(c_p)

    %Point{x: nx, y: ny, z: nz}
  end

  @doc """
  Adds two points in elliptic curves using Jacobian coordinates.

  - `p` [`t:Tezex.Crypto.Point.t/0`]: First Point you want to add (in Jacobian coordinates)
  - `q` [`t:Tezex.Crypto.Point.t/0`]: Second Point you want to add (in Jacobian coordinates)
  - `c_a` [`t:integer/0`]: Coefficient of the first-order term of the equation Y^2 = X^3 + c_a*X + B (mod p)
  - `c_p` [`t:integer/0`]: Prime number in the module of the equation Y^2 = X^3 + c_a*X + B (mod p)

  Returns:
  - `point` [`t:Tezex.Crypto.Point.t/0`]: point that represents the sum of first and second Point in Jacobian coordinates
  """
  @spec jacobian_add(Point.t(), Point.t(), integer(), integer()) :: Point.t()
  def jacobian_add(%Point{y: 0}, q, _c_a, _c_p), do: q
  def jacobian_add(p, %Point{y: 0}, _c_a, _c_p), do: p

  def jacobian_add(p, q, c_a, c_p) do
    u1 =
      (p.x * Utils.ipow(q.z, 2))
      |> Utils.mod(c_p)

    u2 =
      (q.x * Utils.ipow(p.z, 2))
      |> Utils.mod(c_p)

    s1 =
      (p.y * Utils.ipow(q.z, 3))
      |> Utils.mod(c_p)

    s2 =
      (q.y * Utils.ipow(p.z, 3))
      |> Utils.mod(c_p)

    if u1 == u2 do
      if s1 != s2 do
        %Point{x: 0, y: 0, z: 1}
      else
        jacobian_double(p, c_a, c_p)
      end
    else
      h = u2 - u1
      r = s2 - s1

      h2 =
        (h * h)
        |> Utils.mod(c_p)

      h3 =
        (h * h2)
        |> Utils.mod(c_p)

      u1h2 =
        (u1 * h2)
        |> Utils.mod(c_p)

      nx =
        (Utils.ipow(r, 2) - h3 - 2 * u1h2)
        |> Utils.mod(c_p)

      ny =
        (r * (u1h2 - nx) - s1 * h3)
        |> Utils.mod(c_p)

      nz =
        (h * p.z * q.z)
        |> Utils.mod(c_p)

      %Point{x: nx, y: ny, z: nz}
    end
  end

  # Multiply point and scalar on elliptic curves

  # - `p` [`t:Tezex.Crypto.Point.t/0`]: Point to multiply
  # - `n` [`t:integer/0`]: Scalar to multiply
  # - `c_n` [`t:integer/0`]: Order of the elliptic curve
  # - `c_p` [`t:integer/0`]: Prime number in the module of the equation Y^2 = X^3 + c_a*X + B (mod p)
  # - `c_a` [`t:integer/0`]: Coefficient of the first-order term of the equation Y^2 = X^3 + c_a*X + B (mod p)

  # Returns:
  # - `point` [`t:Tezex.Crypto.Point.t/0`]: point that represents the sum of First and Second Point
  @spec jacobian_multiply(Point.t(), integer(), integer(), integer(), integer()) :: Point.t()
  def jacobian_multiply(_p, 0, _c_n, _c_a, _c_p) do
    %Point{x: 0, y: 0, z: 1}
  end

  def jacobian_multiply(p, 1, _c_n, _c_a, _c_p) do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      p
    end
  end

  def jacobian_multiply(p, n, c_n, c_a, c_p) when n < 0 or n >= c_n do
    if p.y == 0 do
      %Point{x: 0, y: 0, z: 1}
    else
      jacobian_multiply(p, Utils.mod(n, c_n), c_n, c_a, c_p)
    end
  end

  def jacobian_multiply(%Point{y: 0}, _n, _c_n, _c_a, _c_p) do
    %Point{x: 0, y: 0, z: 1}
  end

  def jacobian_multiply(p, n, c_n, c_a, c_p) when rem(n, 2) == 0 do
    jacobian_multiply(p, div(n, 2), c_n, c_a, c_p)
    |> jacobian_double(c_a, c_p)
  end

  def jacobian_multiply(p, n, c_n, c_a, c_p) do
    jacobian_multiply(p, div(n, 2), c_n, c_a, c_p)
    |> jacobian_double(c_a, c_p)
    |> jacobian_add(p, c_a, c_p)
  end
end
