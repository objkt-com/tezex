defmodule Tezex.Crypto.Curve do
  @moduledoc false

  @doc """
  Specific elliptic curve data.

  Parameters:
    - `:A` [number]: angular coefficient of x in the curve equation. ex: 123
    - `:B` [number]: linear coefficient of x in the curve equation. ex: 123
    - `:P` [number]: curve modulo. ex: 12345
    - `:N` [number]: curve order. ex: 12345
    - `:G` [%Point]: EC Point corresponding to the public key. ex: %Point{x: 123, y: 456}
    - `:name` [string]: curve name. ex: "secp256k1"
    - `:oid` [list of numbers]: ASN.1 Object Identifier. ex: [1, 3, 132, 0, 10]
  """
  defstruct [:A, :B, :P, :N, :G, :name, :oid]
end
