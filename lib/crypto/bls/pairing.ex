defmodule Tezex.Crypto.BLS.Pairing do
  @moduledoc """
  BLS12-381 pairing operations implementing the Optimal ATE pairing.

  This module provides the pairing function e: G1 × G2 → GT used for BLS signature verification.
  The pairing satisfies the bilinearity property: e(aP, bQ) = e(P, Q)^(ab).

  This is a full implementation of the BLS12-381 pairing using Miller's algorithm
  and final exponentiation.
  """

  alias Tezex.Crypto.BLS.Constants
  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.BLS.Fq12
  alias Tezex.Crypto.BLS.G1
  alias Tezex.Crypto.BLS.G2

  @type gt :: Fq12.t()

  @zero Fq.zero()

  @doc """
  Computes the optimal ATE pairing of a G1 point and G2 point.
  Returns an element in GT = Fq12.

  This implements the full BLS12-381 pairing algorithm:
  1. Miller loop computation
  2. Final exponentiation
  """
  @spec pairing(G1.t(), G2.t()) :: gt()
  def pairing(g1_point, g2_point) do
    pairing(g1_point, g2_point, true)
  end

  @doc """
  Computes the pairing with optional final exponentiation.
  """
  @spec pairing(G1.t(), G2.t(), boolean()) :: gt()
  def pairing(g1_point, g2_point, final_exponentiate) do
    # Handle special cases
    if G1.is_zero?(g1_point) or G2.is_zero?(g2_point) do
      Fq12.one()
    else
      # Verify points are on the correct curves
      unless G1.is_on_curve?(g1_point) do
        raise ArgumentError, "G1 point is not on curve"
      end

      unless G2.is_on_curve?(g2_point) do
        raise ArgumentError, "G2 point is not on curve"
      end

      # Compute Miller loop
      result = miller_loop(g2_point, g1_point, final_exponentiate)

      if final_exponentiate do
        final_exponentiation(result)
      else
        result
      end
    end
  end

  @doc """
  Implements the Miller loop for pairing computation.
  This is the core of the pairing algorithm.

  Core algorithm for optimal ATE pairing computation.
  """
  @spec miller_loop(G2.t(), G1.t(), boolean()) :: gt()
  def miller_loop(q_point, p_point, _final_exponentiate) do
    # Cast P to Fq12 for line function evaluations
    cast_p = cast_point_to_fq12(p_point)

    # Initialize Miller loop variables
    # twist_R = twist_Q = twist(Q)
    twist_q = apply_twist(q_point)
    r_point = q_point
    f_num = Fq12.one()
    f_den = Fq12.one()

    # Main Miller loop
    # for v in pseudo_binary_encoding[62::-1]:
    Constants.pseudo_binary_encoding()
    # Take first 63 elements (0..62)
    |> Enum.take(63)
    # Reverse to match [62::-1]
    |> Enum.reverse()
    |> Enum.reduce({r_point, f_num, f_den}, fn bit, {r, f_n, f_d} ->
      # Apply twist to current R for line function
      twist_r = apply_twist(r)

      # _n, _d = linefunc(twist_R, twist_R, cast_P)
      {line_num, line_den} = line_function_fq12(twist_r, twist_r, cast_p)

      # f_num = f_num * f_num * _n
      # f_den = f_den * f_den * _d
      new_f_n = Fq12.mul(Fq12.mul(f_n, f_n), line_num)
      new_f_d = Fq12.mul(Fq12.mul(f_d, f_d), line_den)

      # R = double(R)
      doubled_r = G2.double(r)

      # twist_R = twist(R)
      doubled_twist_r = apply_twist(doubled_r)

      # Add step if bit is 1
      if bit == 1 do
        # _n, _d = linefunc(twist_R, twist_Q, cast_P)
        # Note: using doubled_twist_r which is twist(doubled_R)
        {add_line_num, add_line_den} = line_function_fq12(doubled_twist_r, twist_q, cast_p)

        # f_num = f_num * _n
        # f_den = f_den * _d
        final_f_n = Fq12.mul(new_f_n, add_line_num)
        final_f_d = Fq12.mul(new_f_d, add_line_den)

        # R = add(R, Q)
        added_r = G2.add(doubled_r, q_point)

        {added_r, final_f_n, final_f_d}
      else
        {doubled_r, new_f_n, new_f_d}
      end
    end)
    |> then(fn {_final_r, final_f_n, final_f_d} ->
      # f = f_num / f_den
      Fq12.field_div(final_f_n, final_f_d)
    end)
  end

  @doc """
  Implements the final exponentiation step of the pairing.
  Uses the optimized BLS12-381 specific algorithm instead of naive exponentiation.
  """
  @spec final_exponentiation(gt()) :: gt()
  def final_exponentiation(miller_result) do
    Fq12.optimized_final_exponentiation(miller_result)
  end

  # Helper functions

  @doc """
  Casts a G1 point to Fq12 coordinates for line function evaluation.
  """
  @spec cast_point_to_fq12(G1.t()) :: %{x: Fq12.t(), y: Fq12.t(), z: Fq12.t()}
  def cast_point_to_fq12(%{x: x, y: y, z: z}) do
    # Convert Fq coordinates to Fq12 by embedding in the base field
    %{
      x: embed_fq_to_fq12(x),
      y: embed_fq_to_fq12(y),
      z: embed_fq_to_fq12(z)
    }
  end

  defp embed_fq_to_fq12(fq_element) do
    # Embed Fq element as the first coefficient of Fq12
    zero = @zero
    Fq12.new([fq_element, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero])
  end

  @doc """
  Computes the line function for Miller's algorithm using Fq12 coordinates.
  This version works with twisted points that have Fq12 coordinates.
  Returns {numerator, denominator} to avoid unnecessary divisions.
  """
  @spec line_function_fq12(
          %{x: Fq12.t(), y: Fq12.t(), z: Fq12.t()},
          %{x: Fq12.t(), y: Fq12.t(), z: Fq12.t()},
          %{x: Fq12.t(), y: Fq12.t(), z: Fq12.t()}
        ) ::
          {Fq12.t(), Fq12.t()}
  def line_function_fq12(p1, p2, t) do
    %{x: x1, y: y1, z: z1} = p1
    %{x: x2, y: y2, z: z2} = p2
    %{x: xt, y: yt, z: zt} = t

    # Compute slope: m = (y2/z2 - y1/z1) / (x2/z2 - x1/z1)
    # Multiply by z1*z2 to avoid divisions
    m_num = Fq12.sub(Fq12.mul(y2, z1), Fq12.mul(y1, z2))
    m_den = Fq12.sub(Fq12.mul(x2, z1), Fq12.mul(x1, z2))

    cond do
      not Fq12.is_zero?(m_den) ->
        # Regular case: different points
        # Line equation: m * (xt - x1) - (yt - y1) = 0
        # Evaluated at T: m * (xt/zt - x1/z1) - (yt/zt - y1/z1)
        line_val =
          Fq12.sub(
            Fq12.mul(m_num, Fq12.sub(Fq12.mul(xt, z1), Fq12.mul(x1, zt))),
            Fq12.mul(m_den, Fq12.sub(Fq12.mul(yt, z1), Fq12.mul(y1, zt)))
          )

        denominator = Fq12.mul(Fq12.mul(m_den, zt), z1)
        {line_val, denominator}

      Fq12.is_zero?(m_num) ->
        # Doubling case: same point or point and its negative
        # Tangent slope: m = 3x1^2 / (2y1*z1)
        three = embed_fq12_from_integer(3)
        two = embed_fq12_from_integer(2)
        three_x1_sq = Fq12.mul(three, Fq12.mul(x1, x1))
        two_y1_z1 = Fq12.mul(two, Fq12.mul(y1, z1))

        line_val =
          Fq12.sub(
            Fq12.mul(three_x1_sq, Fq12.sub(Fq12.mul(xt, z1), Fq12.mul(x1, zt))),
            Fq12.mul(two_y1_z1, Fq12.sub(Fq12.mul(yt, z1), Fq12.mul(y1, zt)))
          )

        denominator = Fq12.mul(Fq12.mul(two_y1_z1, zt), z1)
        {line_val, denominator}

      true ->
        # Vertical line case
        line_val = Fq12.sub(Fq12.mul(xt, z1), Fq12.mul(x1, zt))
        denominator = Fq12.mul(z1, zt)
        {line_val, denominator}
    end
  end

  defp embed_fq12_from_integer(n) do
    fq_element = Fq.from_integer(n)
    embed_fq_to_fq12(fq_element)
  end

  @doc """
  Applies the twist isomorphism to convert G2 points to FQ12.
  Field isomorphism from Z[p] / x**2 to Z[p] / x**2 - 2*x + 2
  """
  @spec apply_twist(G2.t()) :: %{x: Fq12.t(), y: Fq12.t(), z: Fq12.t()}
  def apply_twist(%{x: x, y: y, z: z}) do
    # G2 coordinates are Fq2 elements: {a, b} = a + b*u
    {x_a, x_b} = x
    {y_a, y_b} = y
    {z_a, z_b} = z

    x_coeffs = [Fq.sub(x_a, x_b), x_b]
    y_coeffs = [Fq.sub(y_a, y_b), y_b]
    z_coeffs = [Fq.sub(z_a, z_b), z_b]

    [x0, x1] = x_coeffs
    [y0, y1] = y_coeffs
    [z0, z1] = z_coeffs

    nx_coeffs = [@zero, x0, @zero, @zero, @zero, @zero, @zero, x1, @zero, @zero, @zero, @zero]
    ny_coeffs = [y0, @zero, @zero, @zero, @zero, @zero, y1, @zero, @zero, @zero, @zero, @zero]
    nz_coeffs = [@zero, @zero, @zero, z0, @zero, @zero, @zero, @zero, @zero, z1, @zero, @zero]

    %{
      x: Fq12.new(nx_coeffs),
      y: Fq12.new(ny_coeffs),
      z: Fq12.new(nz_coeffs)
    }
  end

  @doc """
  Returns the identity element in GT.
  """
  @spec gt_identity() :: gt()
  def gt_identity do
    Fq12.one()
  end

  @doc """
  Checks if a GT element is the identity.
  """
  @spec is_identity?(gt()) :: boolean()
  def is_identity?(gt_element) do
    Fq12.is_one?(gt_element)
  end

  @doc """
  Multiplies two GT elements.
  """
  @spec gt_mul(gt(), gt()) :: gt()
  def gt_mul(a, b) do
    Fq12.mul(a, b)
  end

  @doc """
  Inverts a GT element.
  """
  @spec gt_inv(gt()) :: gt()
  def gt_inv(gt_element) do
    Fq12.inv(gt_element)
  end

  @doc """
  Checks if two GT elements are equal.
  """
  @spec gt_eq?(gt(), gt()) :: boolean()
  def gt_eq?(a, b) do
    Fq12.eq?(a, b)
  end

  @doc """
  Performs a pairing check for BLS signature verification.

  Implements the actual BLS verification equation:
  e(signature, G1_generator) == e(H(msg), pubkey)

  This is equivalent to checking:
  e(signature, G1_generator) * e(H(msg), -pubkey) == 1

  Uses the full cryptographically secure pairing implementation.
  """
  @spec pairing_check(G1.t(), G2.t(), G1.t(), G2.t()) :: boolean()
  def pairing_check(pubkey_point, h_msg_point, g1_generator, signature_point) do
    # First, ensure all points are valid (not zero and on curve)
    valid_points =
      not G1.is_zero?(pubkey_point) and
        not G2.is_zero?(h_msg_point) and
        not G2.is_zero?(signature_point) and
        not G1.is_zero?(g1_generator) and
        G1.is_on_curve?(pubkey_point) and
        G2.is_on_curve?(h_msg_point) and
        G2.is_on_curve?(signature_point) and
        G1.is_on_curve?(g1_generator)

    if not valid_points do
      false
    else
      try do
        # Compute the two pairings for BLS verification
        # e1 = e(signature, G1_generator)
        e1 = pairing(g1_generator, signature_point, false)

        # e2 = e(H(msg), pubkey)
        e2 = pairing(pubkey_point, h_msg_point, false)

        # Final exponentiate the product: (e1 * e2^(-1))
        # This is equivalent to checking e1 == e2
        e2_inv = Fq12.inv(e2)
        product = Fq12.mul(e1, e2_inv)
        final_result = final_exponentiation(product)

        # Check if the result is 1 (identity in GT)
        Fq12.is_one?(final_result)
      rescue
        _ -> false
      end
    end
  end
end
