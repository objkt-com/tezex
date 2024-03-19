defmodule Tezex.Crypto.PublicKey do
  @moduledoc """
  Holds public key data.

  Parameters:
  - `:point` [`t:Tezex.Crypto.Point.t/0`]: public key point data;
  - `:curve` [`t:Tezex.Crypto.Curve.t/0`]: public key curve information.
  """
  defstruct [:point, :curve]

  alias Tezex.Crypto.Curve
  alias Tezex.Crypto.KnownCurves
  alias Tezex.Crypto.Math
  alias Tezex.Crypto.Point
  alias Tezex.Crypto.Utils

  @type t :: %__MODULE__{
          point: Point.t(),
          curve: Curve.t()
        }

  @doc false
  def to_string(public_key, encoded \\ false) do
    curve_length = Curve.get_length(public_key.curve)

    x_string =
      Utils.string_from_number(
        public_key.point.x,
        curve_length
      )

    y_string =
      Utils.string_from_number(
        public_key.point.y,
        curve_length
      )

    if encoded do
      "\x00\x04" <> x_string <> y_string
    else
      x_string <> y_string
    end
  end

  @doc false
  def from_string(string, curve \\ :secp256k1, validate_point \\ true) do
    {:ok, from_string!(string, curve, validate_point)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc false
  def from_string!(string, curve \\ :secp256k1, validate_point \\ true) do
    curve = KnownCurves.get_curve_by_name(curve)
    base_length = Curve.get_length(curve)

    xs = binary_part(string, 0, base_length)
    ys = binary_part(string, base_length, byte_size(string) - base_length)

    point = %Point{
      x: Utils.number_from_string(xs),
      y: Utils.number_from_string(ys)
    }

    publicKey = %__MODULE__{point: point, curve: curve}

    cond do
      validate_point == false ->
        publicKey

      Point.is_at_infinity?(point) ->
        raise "Public Key point is at infinity"

      Curve.contains?(curve, point) == false ->
        raise "Point (#{point.x},#{point.y}) is not valid for curve #{curve.name}"

      Point.is_at_infinity?(Math.multiply(point, curve."N", curve."N", curve."A", curve."P")) ==
          false ->
        raise "Point (#{point.x},#{point.y}) * #{curve.name}.N is not at infinity"

      true ->
        publicKey
    end
  end
end
