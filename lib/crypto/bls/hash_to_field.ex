defmodule Tezex.Crypto.BLS.HashToField do
  @moduledoc """
  Hash-to-Field implementation for BLS12-381

  Implements the IRTF standard hash-to-curve specification:
  https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09
  """

  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.BLS.Fq2
  alias Tezex.Crypto.BLS.G2

  # L parameter for hash-to-field (64 bytes for BLS12-381)
  @hash_to_field_l 64
  @modulus Fq.modulus()

  @doc """
  Expand message using XMD (expand message XOR with MD)
  Implementation of expand_message_xmd from IRTF spec section 5.4.1
  """
  @spec expand_message_xmd(binary(), binary(), non_neg_integer()) :: binary()
  def expand_message_xmd(msg, dst, len_in_bytes) when byte_size(dst) <= 255 do
    # SHA-256 digest size
    b_in_bytes = 32
    # SHA-256 block size
    r_in_bytes = 64

    # Ceiling division
    ell = div(len_in_bytes + b_in_bytes - 1, b_in_bytes)

    if ell > 255 do
      raise ArgumentError, "len_in_bytes too large for hash function"
    end

    dst_prime = dst <> <<byte_size(dst)>>
    z_pad = :binary.copy(<<0>>, r_in_bytes)
    l_i_b_str = <<len_in_bytes::big-16>>

    b_0 = :crypto.hash(:sha256, z_pad <> msg <> l_i_b_str <> <<0>> <> dst_prime)
    b_1 = :crypto.hash(:sha256, b_0 <> <<1>> <> dst_prime)
    b_list = [b_1]

    b_list =
      if ell > 1 do
        Enum.reduce(2..ell, b_list, fn i, [b_prev | _rest] = acc ->
          xor_result = :crypto.exor(b_0, b_prev)
          b_i = :crypto.hash(:sha256, xor_result <> <<i>> <> dst_prime)
          [b_i | acc]
        end)
        |> Enum.reverse()
      else
        b_list
      end

    binary_part(IO.iodata_to_binary(b_list), 0, len_in_bytes)
  end

  @doc """
  Hash to field FQ2 - maps a message to FQ2 elements
  """
  @spec hash_to_field_fq2(binary(), non_neg_integer(), binary()) :: list(Fq2.t())
  def hash_to_field_fq2(message, count, dst) do
    # Extension degree of FQ2
    m = 2
    len_in_bytes = count * m * @hash_to_field_l
    pseudo_random_bytes = expand_message_xmd(message, dst, len_in_bytes)

    for i <- 0..(count - 1) do
      coeffs =
        for j <- 0..(m - 1) do
          elem_offset = @hash_to_field_l * (j + i * m)
          tv = binary_part(pseudo_random_bytes, elem_offset, @hash_to_field_l)

          # Convert bytes to integer
          int_val = :binary.decode_unsigned(tv, :big)
          rem(int_val, @modulus)
        end

      [c0, c1] = coeffs
      Fq2.from_integers(c0, c1)
    end
  end

  @doc """
  Complete hash-to-curve implementation for G2 following IRTF standard
  """
  @spec hash_to_g2(binary(), binary()) :: G2.t()
  def hash_to_g2(message, dst \\ "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_") do
    # 1. Hash to field - get 2 FQ2 elements
    field_elements = hash_to_field_fq2(message, 2, dst)
    [u0, u1] = field_elements

    # 2. Map each field element to isogenous curve using SSWU
    {x0, y0, z0} = G2.sswu_map(u0)
    {x1, y1, z1} = G2.sswu_map(u1)

    # 3. Map from isogenous curve to target curve using isogeny
    {x0_mapped, y0_mapped, z0_mapped} = G2.iso_map_g2(x0, y0, z0)
    {x1_mapped, y1_mapped, z1_mapped} = G2.iso_map_g2(x1, y1, z1)

    # 4. Create G2 points from projective coordinates
    p0 = G2.new(x0_mapped, y0_mapped, z0_mapped)
    p1 = G2.new(x1_mapped, y1_mapped, z1_mapped)

    # 5. Add the two points
    result = G2.add(p0, p1)

    # 6. Clear cofactor
    G2.clear_cofactor(result)
  end
end
