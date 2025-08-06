defmodule Tezex.Crypto.BLS.FqP do
  @moduledoc """
  Polynomial extension field base class for BLS12-381.
  This is the base for building higher-degree extension fields like Fq12.
  """

  alias Tezex.Crypto.BLS.Fq

  @type t :: %{coeffs: list(Fq.t()), modulus_coeffs: list(integer())}

  @zero Fq.zero()
  @one Fq.one()
  @modulus Fq.modulus()

  @doc """
  Creates a polynomial extension field element from coefficients.
  """
  @spec new(list(Fq.t()), list(integer())) :: t()
  def new(coeffs, modulus_coeffs) do
    degree = length(modulus_coeffs)

    # Pad or truncate coefficients to match the field degree
    normalized_coeffs =
      coeffs
      |> Enum.take(degree)
      |> pad_to_length(degree)

    %{coeffs: normalized_coeffs, modulus_coeffs: modulus_coeffs}
  end

  @doc """
  Adds two polynomial field elements.
  """
  @spec add(t(), t()) :: t()
  def add(%{coeffs: coeffs1, modulus_coeffs: modulus_coeffs}, %{
        coeffs: coeffs2,
        modulus_coeffs: modulus_coeffs
      }) do
    coeffs = Enum.zip_with(coeffs1, coeffs2, &Fq.add/2)
    new(coeffs, modulus_coeffs)
  end

  @doc """
  Subtracts two polynomial field elements.
  """
  @spec sub(t(), t()) :: t()
  def sub(%{coeffs: coeffs1, modulus_coeffs: modulus_coeffs}, %{
        coeffs: coeffs2,
        modulus_coeffs: modulus_coeffs
      }) do
    coeffs = Enum.zip_with(coeffs1, coeffs2, &Fq.sub/2)
    new(coeffs, modulus_coeffs)
  end

  @doc """
  Multiplies two polynomial field elements with modular reduction.
  This implementation uses an optimized multiplication algorithm.
  """
  @spec mul(t(), t()) :: t()
  def mul(%{coeffs: coeffs1, modulus_coeffs: modulus_coeffs}, %{
        coeffs: coeffs2,
        modulus_coeffs: modulus_coeffs
      }) do
    degree = length(modulus_coeffs)

    # Create b array of size degree * 2 - 1
    b_size = degree * 2 - 1

    # Step 1: Polynomial multiplication - fill b array
    # Use a Map to accumulate products efficiently
    b_map =
      for {c1, i} <- Enum.with_index(coeffs1),
          {c2, j} <- Enum.with_index(coeffs2),
          i + j < b_size,
          reduce: %{} do
        acc ->
          product = Fq.mul(c1, c2)
          Map.update(acc, i + j, product, &Fq.add(&1, product))
      end

    # Step 2: Polynomial reduction
    # Pre-compute modulus coefficients as Fq elements for efficiency
    mc_tuples =
      modulus_coeffs
      |> Enum.with_index()
      |> Enum.reduce([], fn
        {0, _i}, acc -> acc
        {coeff, i}, acc -> [{i, Fq.from_integer(coeff)} | acc]
      end)
      |> Enum.reverse()

    # Step 3: Reduce from degree-2 down to 0
    final_b_map =
      Enum.reduce((degree - 2)..0//-1, b_map, fn exp, acc_map ->
        # Get coefficient at position degree + exp (the "top" term to reduce)
        top_pos = degree + exp
        top = Map.get(acc_map, top_pos, @zero)

        if Fq.is_zero?(top) do
          acc_map
        else
          # Remove the high-degree term
          acc_map = Map.delete(acc_map, top_pos)

          # Apply reduction: for each (i, c) in mc_tuples, b[exp + i] -= top * c
          Enum.reduce(mc_tuples, acc_map, fn
            {i, c}, inner_acc_map when exp + i < b_size ->
              Map.update(inner_acc_map, exp + i, @zero, fn existing ->
                Fq.sub(existing, Fq.mul(top, c))
              end)

            _, inner_acc_map ->
              inner_acc_map
          end)
        end
      end)

    # Step 4: Take first degree coefficients (with field modulus)
    result_coeffs =
      for i <- 0..(degree - 1) do
        coeff = Map.get(final_b_map, i, @zero)
        int_val = Fq.to_integer(coeff)
        Fq.from_integer(rem(int_val, @modulus))
      end

    new(result_coeffs, modulus_coeffs)
  end

  @doc """
  Negates a polynomial field element.
  """
  @spec neg(t()) :: t()
  def neg(%{coeffs: coeffs, modulus_coeffs: modulus_coeffs}) do
    new(Enum.map(coeffs, &Fq.neg/1), modulus_coeffs)
  end

  @doc """
  Returns the zero element.
  """
  @spec zero(list(integer())) :: t()
  def zero(modulus_coeffs) do
    degree = length(modulus_coeffs)
    zero_coeffs = List.duplicate(@zero, degree)
    new(zero_coeffs, modulus_coeffs)
  end

  @doc """
  Returns the one element.
  """
  @spec one(list(integer())) :: t()
  def one(modulus_coeffs) do
    degree = length(modulus_coeffs)
    one_coeffs = [@one | List.duplicate(@zero, degree - 1)]
    new(one_coeffs, modulus_coeffs)
  end

  @doc """
  Checks if the element is zero.
  """
  @spec is_zero?(t()) :: boolean()
  def is_zero?(%{coeffs: coeffs}) do
    Enum.all?(coeffs, &Fq.is_zero?/1)
  end

  @doc """
  Checks if two elements are equal.
  """
  @spec eq?(t(), t()) :: boolean()
  def eq?(%{coeffs: coeffs1, modulus_coeffs: modulus_coeffs}, %{
        coeffs: coeffs2,
        modulus_coeffs: modulus_coeffs
      }) do
    Enum.zip(coeffs1, coeffs2)
    |> Enum.all?(fn {a, b} -> Fq.eq?(a, b) end)
  end

  @doc """
  Computes the modular inverse using the extended Euclidean algorithm.
  Polynomial inversion using extended Euclidean algorithm.
  """
  @spec inv(t()) :: t()
  def inv(%{coeffs: coeffs, modulus_coeffs: modulus_coeffs} = elem) do
    if is_zero?(elem) do
      raise ArithmeticError, "Cannot invert zero element"
    end

    polynomial_inv(coeffs, modulus_coeffs)
  end

  # Helper functions

  defp pad_to_length(list, target_length) do
    current_length = length(list)

    if current_length < target_length do
      list ++ List.duplicate(@zero, target_length - current_length)
    else
      list
    end
  end

  defp polynomial_inv(coeffs, modulus_coeffs) do
    degree = length(modulus_coeffs)

    lm = [@one | List.duplicate(@zero, degree)]
    hm = List.duplicate(@zero, degree + 1)
    low = coeffs ++ [@zero]
    high = Enum.map(modulus_coeffs, &Fq.from_integer/1) ++ [@one]

    {final_lm, final_low} = extended_gcd_loop(lm, hm, low, high, degree)

    low0_int = Fq.to_integer(hd(final_low))
    inv_low0_int = prime_field_inv(low0_int, @modulus)

    coeffs =
      final_lm
      |> Enum.take(degree)
      |> Enum.map(fn coeff ->
        coeff_int = Fq.to_integer(coeff)
        result_int = rem(coeff_int * inv_low0_int, @modulus)
        Fq.from_integer(result_int)
      end)

    new(coeffs, modulus_coeffs)
  end

  # Extended GCD loop
  defp extended_gcd_loop(lm, hm, low, high, degree) do
    case deg(low) do
      0 ->
        {lm, low}

      _ ->
        r = optimized_poly_rounded_div(high, low)
        r_padded = r ++ List.duplicate(@zero, degree + 1 - length(r))

        {nm, new} =
          Enum.reduce(0..degree, {hm, high}, fn i, {nm_acc, acc} ->
            Enum.reduce(0..(degree - i), {nm_acc, acc}, fn
              j, {nm_inner, inner} when i + j <= degree ->
                nm_val = Enum.at(nm_inner, i + j)
                lm_val = Enum.at(lm, i)
                r_val = Enum.at(r_padded, j)

                nm_val = Fq.sub(nm_val, Fq.mul(lm_val, r_val))

                val = Enum.at(inner, i + j)
                low_val = Enum.at(low, i)
                val = Fq.sub(val, Fq.mul(low_val, r_val))

                {List.replace_at(nm_inner, i + j, nm_val), List.replace_at(inner, i + j, val)}

              _j, {nm_inner, inner} ->
                {nm_inner, inner}
            end)
          end)

        nm_mod =
          Enum.map(nm, fn x ->
            Fq.from_integer(rem(Fq.to_integer(x), @modulus))
          end)

        mod =
          Enum.map(new, fn x ->
            Fq.from_integer(rem(Fq.to_integer(x), @modulus))
          end)

        extended_gcd_loop(nm_mod, lm, mod, low, degree)
    end
  end

  defp deg(p) do
    deg_helper(p, length(p) - 1)
  end

  defp deg_helper(_p, 0), do: 0

  defp deg_helper(p, d) do
    if Fq.is_zero?(Enum.at(p, d)) and d > 0 do
      deg_helper(p, d - 1)
    else
      d
    end
  end

  defp optimized_poly_rounded_div(a_list, b_list) do
    deg_a = deg(a_list)
    deg_b = deg(b_list)

    tmp = Enum.map(a_list, & &1)
    o = List.duplicate(@zero, length(a_list))

    {o, _} =
      Enum.reduce((deg_a - deg_b)..0//-1, {o, tmp}, fn i, {o_acc, tmp_acc} ->
        if i >= 0 and deg_b + i < length(tmp_acc) and deg_b < length(b_list) do
          tmp_val = Enum.at(tmp_acc, deg_b + i)
          b_val = Enum.at(b_list, deg_b)

          b_int =
            Fq.to_integer(b_val)
            |> prime_field_inv(@modulus)

          o_val =
            (Fq.to_integer(Enum.at(o_acc, i)) + Fq.to_integer(tmp_val) * b_int)
            |> Fq.from_integer()

          o = List.replace_at(o_acc, i, o_val)

          tmp =
            Enum.reduce(0..deg_b, tmp_acc, fn c, tmp_inner ->
              if c + i < length(tmp_inner) and c < length(o) do
                tmp_c_i = Enum.at(tmp_inner, c + i)
                o_c = Enum.at(o, c)
                List.replace_at(tmp_inner, c + i, Fq.sub(tmp_c_i, o_c))
              else
                tmp_inner
              end
            end)

          {o, tmp}
        else
          {o_acc, tmp_acc}
        end
      end)

    o
    |> Enum.take(deg(o) + 1)
    |> Enum.map(fn x ->
      int_val = Fq.to_integer(x)
      Fq.from_integer(rem(int_val, @modulus))
    end)
  end

  # prime_field_inv function
  defp prime_field_inv(a, n) do
    # To address a == n edge case.
    a = rem(a, n)

    if a == 0 do
      0
    else
      {lm, _low} = prime_field_inv_loop(1, 0, rem(a, n), n)

      # Ensure the result is positive
      result = rem(lm, n)

      if result < 0 do
        result + n
      else
        result
      end
    end
  end

  defp prime_field_inv_loop(lm, hm, low, high) do
    if low > 1 do
      r = div(high, low)
      nm = hm - lm * r
      new = high - low * r
      # lm, low, hm, high = nm, new, lm, low
      prime_field_inv_loop(nm, lm, new, low)
    else
      {lm, low}
    end
  end
end
