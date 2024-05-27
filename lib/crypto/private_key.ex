defmodule Tezex.Crypto.PrivateKey do
  @moduledoc """
  Holds private key data.

  Used to create private keys and created public keys from private keys.

  Parameters:
  - `:secret` [`t:binary/0`]: public key point data;
  - `:curve` [`t:Tezex.Crypto.Curve.t/0`]: public key curve information.
  """

  alias Tezex.Crypto.Curve
  alias Tezex.Crypto.KnownCurves
  alias Tezex.Crypto.Math
  alias Tezex.Crypto.PrivateKey
  alias Tezex.Crypto.PublicKey
  alias Tezex.Crypto.Utils

  @type t :: %__MODULE__{
          secret: binary(),
          curve: Curve.t()
        }

  @doc """
  Holds private key data.

  Parameters:
  - `:secret` [`t:binary/0`]: private key secret number as bytes
  - `:curve` [`t:Tezex.Crypto.Curve.t/0`]: private key curve information
  """
  defstruct [:secret, :curve]

  @doc """
  Creates a new private key

  Parameters:
  - `secret` [`t:binary/0`]: private key secret. Default: nil -> random key will be generated
  - `curve_name` [`t:atom/0`]: curve name. Default: :secp256k1

  Returns:
  - `private_key` [`t:Tezex.Crypto.PrivateKey.t/0`]: private key struct

  ## Example:

      iex> Tezex.Crypto.PrivateKey.generate()
      %Tezex.Crypto.PrivateKey{...}
  """
  @spec generate(nil | binary()) :: t()
  @spec generate(nil | binary(), atom()) :: t()
  def generate(secret \\ nil, curve_name \\ :secp256k1)

  def generate(secret, curve_name) when is_nil(secret) do
    curve = KnownCurves.get_curve_by_name(curve_name)

    Utils.between(1, curve."N" - 1)
    |> Utils.string_from_number(Curve.get_length(curve))
    |> generate(curve_name)
  end

  def generate(secret, curve_name) when is_binary(secret) and is_atom(curve_name) do
    %PrivateKey{
      secret: secret,
      curve: KnownCurves.get_curve_by_name(curve_name)
    }
  end

  @doc """
  Gets the public key associated with a private key

  Parameters:
  - `private_key` [`t:Tezex.Crypto.PrivateKey.t/0`]: private key struct

  Returns:
  - `public_key` [`t:Tezex.Crypto.PublicKey.t/0`]: public key struct

  ## Example:

      iex> Tezex.Crypto.PrivateKey.get_public_key(private_key)
      %Tezex.Crypto.PublicKey{...}
  """
  @spec get_public_key(t()) :: PublicKey.t()
  def get_public_key(private_key) do
    curve = private_key.curve
    secret = Utils.number_from_string(private_key.secret)

    %PublicKey{
      point: Math.multiply(curve."G", secret, curve."N", curve."A", curve."P"),
      curve: curve
    }
  end

  @doc false
  @spec to_string(t()) :: binary()
  def to_string(private_key) do
    private_key.secret
  end

  @doc false
  @spec from_string(binary()) :: {:error, map()} | {:ok, t()}
  def from_string(string, curve \\ :secp256k1) do
    {:ok, from_string!(string, curve)}
  rescue
    e in RuntimeError -> {:error, e}
  end

  @doc false
  def from_string!(string, curve \\ :secp256k1) when is_binary(string) do
    curve = KnownCurves.get_curve_by_name(curve)

    n =
      Utils.number_from_string(string)
      |> Utils.mod(curve."N")
      |> Utils.string_from_number(Curve.get_length(curve))

    %PrivateKey{
      secret: n,
      curve: curve
    }
  end
end
