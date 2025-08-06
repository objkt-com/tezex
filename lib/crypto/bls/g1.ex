defmodule Tezex.Crypto.BLS.G1 do
  @moduledoc """
  G1 elliptic curve group for BLS12-381.

  This is the elliptic curve E(Fq): y² = x³ + 4 over the base field Fq.
  G1 is used for public keys in BLS signatures.

  Points are represented in projective coordinates (X, Y, Z) where:
  - Affine coordinates: (X/Z, Y/Z) - standard projective coordinate system
  - Point at infinity: (1, 1, 0)
  """

  import Bitwise
  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.BLS.Fr

  @type t :: %{x: Fq.t(), y: Fq.t(), z: Fq.t()}

  # Curve coefficient B = 4
  @curve_b_int 4
  @i_curve_b_int Fq.from_integer(@curve_b_int)

  # Generator point coordinates (affine)
  @generator_x_int 3_685_416_753_713_387_016_781_088_315_183_077_757_961_620_795_782_546_409_894_578_378_688_607_592_378_376_318_836_054_947_676_345_821_548_104_185_464_507
  @generator_y_int 1_339_506_544_944_476_473_020_471_379_941_921_221_584_933_875_938_349_620_426_543_736_416_511_423_956_333_506_472_724_655_353_366_534_992_391_756_441_569

  @zero Fq.zero()
  @one Fq.one()
  @generator_x Fq.from_integer(@generator_x_int)
  @generator_y Fq.from_integer(@generator_y_int)
  @modulus Fq.modulus()

  @i_2 Fq.from_integer(2)
  @i_3 Fq.from_integer(3)
  @i_4 Fq.from_integer(4)
  @i_8 Fq.from_integer(8)

  @doc """
  Creates a G1 point from Jacobian coordinates.
  """
  @spec new(Fq.t(), Fq.t(), Fq.t()) :: t()
  def new(x, y, z) do
    %{x: x, y: y, z: z}
  end

  @doc """
  Returns the point at infinity (identity element).
  """
  @spec zero() :: t()
  def zero do
    new(@one, @one, @zero)
  end

  @doc """
  Returns the generator point for G1.
  """
  @spec generator() :: t()
  def generator do
    x = @generator_x
    y = @generator_y
    z = @one
    new(x, y, z)
  end

  @doc """
  Checks if a point is the point at infinity.
  """
  @spec is_zero?(t()) :: boolean()
  def is_zero?(%{z: z}) do
    Fq.is_zero?(z)
  end

  @doc """
  Alias for is_zero?/1 for compatibility.
  """
  @spec is_infinity?(t()) :: boolean()
  def is_infinity?(point), do: is_zero?(point)

  @doc """
  Checks if a point is on the curve using Jacobian coordinates.
  Standard curve equation: y² * z = x³ + b * z³
  """
  @spec is_on_curve?(t()) :: boolean()
  def is_on_curve?(point) do
    if is_zero?(point) do
      true
    else
      %{x: x, y: y, z: z} = point

      # Check curve equation in Jacobian coordinates: y² * z = x³ + b * z³
      # This avoids the precision issues of converting to affine coordinates
      y_squared = Fq.square(y)
      y_squared_times_z = Fq.mul(y_squared, z)

      x_cubed = Fq.mul(Fq.square(x), x)
      z_cubed = Fq.mul(Fq.square(z), z)
      b_times_z_cubed = Fq.mul(@i_curve_b_int, z_cubed)
      x_cubed_plus_b_z_cubed = Fq.add(x_cubed, b_times_z_cubed)

      Fq.eq?(y_squared_times_z, x_cubed_plus_b_z_cubed)
    end
  end

  @doc """
  Doubles a G1 point.
  """
  @spec double(t()) :: t()
  def double(point) do
    if is_zero?(point) do
      zero()
    else
      %{x: x, y: y, z: z} = point

      w = Fq.mul(@i_3, Fq.square(x))
      s = Fq.mul(y, z)
      b = Fq.mul(Fq.mul(x, y), s)
      h = Fq.sub(Fq.square(w), Fq.mul(@i_8, b))
      s_squared = Fq.square(s)

      x = Fq.mul(Fq.mul(@i_2, h), s)

      y =
        Fq.sub(
          Fq.mul(w, Fq.sub(Fq.mul(@i_4, b), h)),
          Fq.mul(Fq.mul(@i_8, Fq.square(y)), s_squared)
        )

      z = Fq.mul(@i_8, Fq.mul(s, s_squared))

      new(x, y, z)
    end
  end

  @doc """
  Adds two G1 points using standard elliptic curve addition.
  """
  @spec add(t(), t()) :: t()
  def add(p1, p2) do
    cond do
      is_zero?(p1) -> p2
      is_zero?(p2) -> p1
      true -> add_projective_algorithm(p1, p2)
    end
  end

  # Projective addition algorithm implementation
  defp add_projective_algorithm(p1, p2) do
    %{x: x1, y: y1, z: z1} = p1
    %{x: x2, y: y2, z: z2} = p2

    u1 = Fq.mul(y2, z1)
    u2 = Fq.mul(y1, z2)
    v1 = Fq.mul(x2, z1)
    v2 = Fq.mul(x1, z2)

    cond do
      Fq.eq?(v1, v2) and Fq.eq?(u1, u2) ->
        double(p1)

      Fq.eq?(v1, v2) ->
        # Point at infinity
        zero()

      true ->
        u = Fq.sub(u1, u2)
        v = Fq.sub(v1, v2)
        v_squared = Fq.square(v)
        v_squared_times_v2 = Fq.mul(v_squared, v2)
        v_cubed = Fq.mul(v, v_squared)
        w = Fq.mul(z1, z2)

        a =
          Fq.sub(
            Fq.sub(Fq.mul(Fq.square(u), w), v_cubed),
            Fq.mul(@i_2, v_squared_times_v2)
          )

        x = Fq.mul(v, a)
        y = Fq.sub(Fq.mul(u, Fq.sub(v_squared_times_v2, a)), Fq.mul(v_cubed, u2))
        z = Fq.mul(v_cubed, w)

        new(x, y, z)
    end
  end

  @doc """
  Negates a G1 point.
  """
  @spec negate(t()) :: t()
  def negate(point) do
    if is_zero?(point) do
      zero()
    else
      new(point.x, Fq.neg(point.y), point.z)
    end
  end

  @doc """
  Multiplies a G1 point by a scalar using binary "double-and-add".
  """
  @spec mul(t(), Fr.t()) :: t()
  def mul(point, scalar) when byte_size(scalar) == 32 do
    scalar_int = Fr.to_integer(scalar)
    mul_recursive(point, scalar_int)
  end

  # Recursive scalar multiplication
  defp mul_recursive(_point, 0) do
    # Point at infinity
    zero()
  end

  defp mul_recursive(point, 1) do
    point
  end

  defp mul_recursive(point, n) when rem(n, 2) == 0 do
    doubled = double(point)
    mul_recursive(doubled, div(n, 2))
  end

  defp mul_recursive(point, n) do
    doubled = double(point)
    multiplied = mul_recursive(doubled, div(n, 2))
    add(multiplied, point)
  end

  @doc """
  Checks if two G1 points are equal.
  """
  @spec eq?(t(), t()) :: boolean()
  def eq?(p1, p2) do
    cond do
      is_zero?(p1) and is_zero?(p2) -> true
      is_zero?(p1) or is_zero?(p2) -> false
      true -> eq_different?(p1, p2)
    end
  end

  # Check equality for non-zero points
  defp eq_different?(p1, p2) do
    %{x: x1, y: y1, z: z1} = p1
    %{x: x2, y: y2, z: z2} = p2

    # x1*z2 == x2*z1 and y1*z2 == y2*z1
    x1_cross = Fq.mul(x1, z2)
    x2_cross = Fq.mul(x2, z1)

    if Fq.eq?(x1_cross, x2_cross) do
      y1_cross = Fq.mul(y1, z2)
      y2_cross = Fq.mul(y2, z1)
      Fq.eq?(y1_cross, y2_cross)
    else
      false
    end
  end

  @doc """
  Converts a G1 point to affine coordinates using projective coordinate system
  where affine = (x/z, y/z), not Jacobian (x/z^2, y/z^3).
  """
  @spec to_affine(t()) :: {:ok, {Fq.t(), Fq.t()}} | {:error, :point_at_infinity}
  def to_affine(point) do
    with false <- is_zero?(point),
         %{x: x, y: y, z: z} = point,
         {:ok, z_inv} <- Fq.inv(z) do
      affine_x = Fq.mul(x, z_inv)
      affine_y = Fq.mul(y, z_inv)

      {:ok, {affine_x, affine_y}}
    else
      _ -> {:error, :point_at_infinity}
    end
  end

  @doc """
  Creates a G1 point from affine coordinates.
  """
  @spec from_affine(Fq.t(), Fq.t()) :: t()
  def from_affine(x, y) do
    new(x, y, @one)
  end

  # Bit shift constants for compressed encoding
  @pow_2_381 1 <<< 381
  @pow_2_382 1 <<< 382
  @pow_2_383 1 <<< 383
  @infinity <<@pow_2_383 + @pow_2_382::big-integer-size(384)>>

  @doc """
  Serializes a G1 point to compressed format (48 bytes).
  """
  @spec to_compressed_bytes(t()) :: binary()
  def to_compressed_bytes(point) do
    with false <- is_zero?(point),
         {:ok, {x, y}} <- to_affine(point) do
      x_int = Fq.to_integer(x)
      y_int = Fq.to_integer(y)
      field_modulus = @modulus

      a_flag = if 2 * y_int >= field_modulus, do: 1, else: 0

      compressed_value = x_int + a_flag * @pow_2_381 + @pow_2_383

      <<compressed_value::big-integer-size(384)>>
    else
      _ ->
        # Point at infinity fallback
        @infinity
    end
  end

  @doc """
  Deserializes a G1 point from compressed format (48 bytes).
  """
  @spec from_compressed_bytes(binary()) :: {:ok, t()} | {:error, :invalid_point}
  def from_compressed_bytes(bytes) when byte_size(bytes) == 48 do
    <<first_byte, rest::binary>> = bytes

    # Check compression flag
    with true <- (first_byte &&& 0x80) != 0,
         # Point at infinity check
         true <- (first_byte &&& 0x40) == 0 or :maybe_inf,
         # Extract x coordinate and y parity
         y_parity = (first_byte &&& 0x20) >>> 5,
         x_first_byte = first_byte &&& 0x1F,
         x_bytes = <<x_first_byte>> <> rest,
         {:ok, x} <- Fq.from_bytes(x_bytes),
         # Compute y coordinate from curve equation: y² = x³ + 4
         x_cubed = Fq.mul(Fq.square(x), x),
         y_squared = Fq.add(x_cubed, @i_curve_b_int),
         {:ok, y} <- Fq.sqrt(y_squared) do
      # Choose correct y based on lexicographically larger convention
      # a_flag = 1 if y > q/2, 0 otherwise
      y_int = Fq.to_integer(y)
      field_modulus = @modulus
      computed_a_flag = if 2 * y_int >= field_modulus, do: 1, else: 0

      if computed_a_flag == y_parity do
        point = from_affine(x, y)
        {:ok, point}
      else
        neg_y = Fq.neg(y)
        point = from_affine(x, neg_y)
        {:ok, point}
      end
    else
      :maybe_inf ->
        if bytes == <<0xC0, 0::376>> do
          {:ok, zero()}
        else
          {:error, :invalid_point}
        end

      _ ->
        {:error, :invalid_point}
    end
  end

  def from_compressed_bytes(_), do: {:error, :invalid_point}
end
