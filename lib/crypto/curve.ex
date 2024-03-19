defmodule Tezex.Crypto.Curve do
  @moduledoc """
  Specific elliptic curve data.

  Parameters:
    - `:A` [`t:non_neg_integer/0`]: angular coefficient of x in the curve equation. ex: 123
    - `:B` [`t:non_neg_integer/0`]: linear coefficient of x in the curve equation. ex: 123
    - `:P` [`t:non_neg_integer/0`]: curve modulo. ex: 12345
    - `:N` [`t:non_neg_integer/0`]: curve order. ex: 12345
    - `:G` [`t:Tezex.Crypto.Point.t/0`]: EC Point corresponding to the public key. ex: `%Tezex.Crypto.Point{x: 123, y: 456}`
    - `:name` [`t:atom/0`]: curve name. ex: :secp256k1
  """
  defstruct [:A, :B, :P, :N, :G, :name]

  alias Tezex.Crypto.Point
  alias Tezex.Crypto.Utils

  @type t :: %__MODULE__{
          name: atom(),
          A: non_neg_integer(),
          B: non_neg_integer(),
          P: non_neg_integer(),
          N: non_neg_integer(),
          G: Point.t()
        }

  @doc """
  Verifies if the point `p` is on the curve using the elliptic curve equation:
  y^2 = x^3 + A*x + B (mod P)

  Parameters:
  - `curve` [`t:Tezex.Crypto.Curve.t/0`]: curve data
  - `p` [`t:Tezex.Crypto.Point.t/0`]: curve point

  Returns:
  - `result` [`t:boolean/0`]: true if point is on the curve, false otherwise
  """
  @spec contains?(t(), Point.t()) :: boolean()
  def contains?(curve, p) do
    cond do
      p.x < 0 || p.x > curve."P" - 1 ->
        false

      p.y < 0 || p.y > curve."P" - 1 ->
        false

      (Utils.ipow(p.y, 2) - (Utils.ipow(p.x, 3) + curve."A" * p.x + curve."B"))
      |> Utils.mod(curve."P") != 0 ->
        false

      true ->
        true
    end
  end

  @doc """
  Get the curve length

  Parameters:
  - `curve` [`t:Tezex.Crypto.Curve.t/0`]: curve data

  Returns:
  - `length` [`t:non_neg_integer/0`]: curve length
  """
  @spec get_length(t()) :: non_neg_integer()
  def get_length(curve) do
    div(1 + String.length(Integer.to_string(curve."N", 16)), 2)
  end
end
