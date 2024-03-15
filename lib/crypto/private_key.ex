defmodule Tezex.Crypto.PrivateKey do
  @moduledoc """
  Used to create private keys or convert them between struct and .der or .pem formats. Also allows creations of public keys from private keys.
  """

  alias Tezex.Crypto.Curve
  alias Tezex.Crypto.KnownCurves
  alias Tezex.Crypto.Math
  alias Tezex.Crypto.Point
  alias Tezex.Crypto.PrivateKey
  alias Tezex.Crypto.PublicKey
  alias Tezex.Crypto.Utils

  @type t :: %__MODULE__{
          secret: any(),
          curve: Curve.t()
        }

  @doc """
  Holds private key data.

  Parameters:
  - `:secret` [integer]: private key secret number
  - `:curve` [%Tezex.Crypto.Curve]: private key curve information
  """
  defstruct [:secret, :curve]

  @doc """
  Creates a new private key

  Parameters:
  - `secret` [integer]: private key secret. Default: nil -> random key will be generated
  - `curve` [atom]: curve name. Default: :secp256k1

  Returns:
  - `private_key` [%Tezex.Crypto.PrivateKey]: private key struct

  ## Example:

      iex> Tezex.Crypto.PrivateKey.generate()
      %Tezex.Crypto.PrivateKey{...}
  """
  def generate(secret \\ nil, curve \\ :secp256k1)

  def generate(secret, curve) when is_nil(secret) do
    generate(Utils.between(1, KnownCurves.get_curve_by_name(curve)."N" - 1), curve)
  end

  def generate(secret, curve) do
    %PrivateKey{
      secret: secret,
      curve: KnownCurves.get_curve_by_name(curve)
    }
  end

  @doc """
  Gets the public associated with a private key

  Parameters:
  - `private_key` [%Tezex.Crypto.PrivateKey]: private key struct

  Returns:
  - `public_key` [%Tezex.Crypto.PublicKey]: public key struct

  ## Example:

      iex> Tezex.Crypto.PrivateKey.get_public_key(private_key)
      %Tezex.Crypto.PublicKey{...}
  """
  def get_public_key(private_key) do
    curve = private_key.curve

    %PublicKey{
      point: Math.multiply(curve."G", private_key.secret, curve."N", curve."A", curve."P"),
      curve: curve
    }
  end

  @doc false
  def to_string(private_key) do
    Utils.string_from_number(private_key.secret, Curve.get_length(private_key.curve))
  end

  @doc false
  def from_string(string, curve \\ :secp256k1) do
    {:ok, from_string!(string, curve)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc false
  def from_string!(string, curve \\ :secp256k1) do
    curve = KnownCurves.get_curve_by_name(curve)

    n =
      Utils.number_from_string(string)
      |> Utils.mod(curve."N")

    %PrivateKey{
      secret: n,
      curve: curve
    }
  end

  def to_point(%PrivateKey{} = pk) do
    curve = pk.curve
    g = curve."G"
    g = %Point{x: g.x, y: g.y, z: 0}

    Math.multiply(g, pk.secret, curve."N", curve."A", curve."P")
  end
end
