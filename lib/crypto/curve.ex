defmodule Tezex.Crypto.Curve do
  @moduledoc """
  Specific elliptic curve data.

  Parameters:
    - `:A` [number]: angular coefficient of x in the curve equation. ex: 123
    - `:B` [number]: linear coefficient of x in the curve equation. ex: 123
    - `:P` [number]: curve modulo. ex: 12345
    - `:N` [number]: curve order. ex: 12345
    - `:G` [%Point]: EC Point corresponding to the public key. ex: %Point{x: 123, y: 456}
    - `:name` [atom]: curve name. ex: :secp256k1
  """
  defstruct [:A, :B, :P, :N, :G, :name]

  alias Tezex.Crypto.Point

  @type t :: %__MODULE__{
          name: atom(),
          A: non_neg_integer,
          B: non_neg_integer,
          P: non_neg_integer,
          N: non_neg_integer,
          G: Point.t()
        }

  @doc """
  Get the curve length

  Parameters:
  - `curve` [%Tezex.Crypto.Curve]: curve data

  Returns:
  - `length` [integer]: curve length
  """
  @spec get_length(t()) :: non_neg_integer()
  def get_length(curve) do
    div(1 + String.length(Integer.to_string(curve."N", 16)), 2)
  end
end
