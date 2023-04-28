defmodule Tezex.Crypto.ECDSA do
  @moduledoc """
  Decode compressed public key and verify signatures using the Elliptic Curve Digital Signature Algorithm (ECDSA).
  """

  alias EllipticCurve.Utils.Integer, as: IntegerUtils
  alias EllipticCurve.Utils.BinaryAscii
  alias EllipticCurve.{Point, PublicKey, Math}
  alias EllipticCurve.Curve.KnownCurves

  @doc """
  Decodes a compressed public key to the EC public key it is representing on EC `curve`.

  Here is a sample `curve`, P-256 with curve parameters from <https://neuromancer.sk/std/nist/>:

  ```elixir
  %EllipticCurve.Curve{
      name: :prime256v1,
      A: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
      B: 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
      P: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
      N: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
      G: %Point{
        x: 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        y: 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
      },
      oid: [1, 2, 840, 10045, 3, 1, 7]
    }
  ```

  Parameters:
  - `compressed_pubkey` [`binary`]: the public key to decode
  - `curve` [`%EllipticCurve.Curve{}`]: the curve to use (or one of `:prime256v1`, `:secp256k1` for the two known curves supported by default)

  Returns:
  - public_key [`%EllipticCurve.PublicKey{}`]: a struct containing the public point and the curve;
  """
  def decode_public_key(compressed_pubkey, curve_name) when is_atom(curve_name) do
    curve = KnownCurves.getCurveByName(curve_name)
    decode_public_key(compressed_pubkey, curve)
  end

  def decode_public_key(compressed_pubkey, curve) do
    %PublicKey{point: decode_point(compressed_pubkey, curve), curve: curve}
  end

  def decode_point(compressed_pubkey, %EllipticCurve.Curve{name: :prime256v1} = curve) do
    prime = curve."P"

    b = curve."B"

    p_ident = div(prime + 1, 4)
    <<sign_y::unsigned-integer-8>> <> x = compressed_pubkey
    sign_y = rem(sign_y, 2)

    x = :binary.decode_unsigned(x)
    a = x ** 3 - x * 3 + b

    y =
      :crypto.mod_pow(a, p_ident, prime)
      |> :binary.decode_unsigned()
      |> then(fn y ->
        if rem(y, 2) == sign_y do
          y
        else
          prime - y
        end
      end)

    %Point{x: x, y: y}
  end

  def decode_point(compressed_pubkey, %EllipticCurve.Curve{name: :secp256k1} = curve) do
    # Determine the prefix of the compressed public key and parse the x-coordinate from the compressed public key
    <<prefix::unsigned-integer-8>> <> x = compressed_pubkey
    x = :binary.decode_unsigned(x)

    p = curve."P"

    # Compute the square of the x-coordinate
    x_squared =
      :crypto.mod_pow(x, 3, p)
      |> :binary.decode_unsigned()

    # Compute the right-hand side of the secp256k1 equation
    y_squared = mod_add(x_squared, 7, p)

    # Compute the square root of y_squared modulo p
    y = :crypto.mod_pow(y_squared, div(p + 1, 4), p) |> :binary.decode_unsigned()

    # Choose the correct y-coordinate based on the prefix
    y =
      if rem(prefix, 2) == 0 do
        # If the prefix is even, choose the even value of y
        y_even = y
        y_odd = mod_sub(p, y_even, p)
        if rem(y_odd, 2) == 0, do: y_odd, else: y_even
      else
        # If the prefix is odd, choose the odd value of y
        y_odd = y
        y_even = mod_sub(p, y_odd, p)
        if rem(y_even, 2) == 0, do: y_even, else: y_odd
      end

    %Point{x: x, y: y}
  end

  @doc """
  Verifies a message signature based on a public key

  Parameters:
  - `message` [`binary`]: message that was signed
  - `signature` [`%EllipticCurve.Signature{}`]: signature associated with the message
  - `public_key` [`%EllipticCurve.PublicKey{}`]: public key associated with the message signer
  - `options` [`kw list`]: refines request
    - `:hashfunc` [`fun/1`]: hash function applied to the message. Default: `fn msg -> :crypto.hash(:sha256, msg) end`

  Returns:
  - verified [`bool`]: true if message, public key and signature are compatible, false otherwise
  """
  def verify?(message, signature, public_key, options \\ []) do
    # basically https://github.com/starkbank/ecdsa-elixir/blob/ab5b3914ae2ee47cb87bdfe471871943c4761523/lib/ecdsa.ex#L77
    # but with more customizable hashfunc
    %{hashfunc: hashfunc} =
      Enum.into(options, %{hashfunc: fn msg -> :crypto.hash(:sha256, msg) end})

    number_message =
      hashfunc.(message)
      |> BinaryAscii.numberFromString()

    curve_data = public_key.curve

    inv = Math.inv(signature.s, curve_data."N")

    v =
      Math.add(
        Math.multiply(
          curve_data."G",
          IntegerUtils.modulo(number_message * inv, curve_data."N"),
          curve_data."N",
          curve_data."A",
          curve_data."P"
        ),
        Math.multiply(
          public_key.point,
          IntegerUtils.modulo(signature.r * inv, curve_data."N"),
          curve_data."N",
          curve_data."A",
          curve_data."P"
        ),
        curve_data."A",
        curve_data."P"
      )

    cond do
      signature.r < 1 or signature.r >= curve_data."N" -> false
      signature.s < 1 or signature.s >= curve_data."N" -> false
      Point.isAtInfinity?(v) -> false
      IntegerUtils.modulo(v.x, curve_data."N") != signature.r -> false
      true -> true
    end
  end

  defp mod_add(left, right, modulus) do
    rem(left + right, modulus)
  end

  defp mod_sub(left, right, modulus) do
    rem(left - right, modulus)
  end
end
