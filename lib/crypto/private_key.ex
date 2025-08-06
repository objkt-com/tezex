defmodule Tezex.Crypto.PrivateKey do
  @moduledoc """
  Holds private key data.

  Used to create private keys and created public keys from private keys.

  Parameters:
  - `:secret` [`t:binary/0`]: public key point data;
  - `:curve` [`t:Tezex.Crypto.Curve.t/0`]: public key curve information.
  """

  alias Tezex.Crypto.Base58Check
  alias Tezex.Crypto.Curve
  alias Tezex.Crypto.KnownCurves
  alias Tezex.Crypto.Math
  alias Tezex.Crypto.NaCl
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

  @doc """
  Creates a private key from a Tezos encoded key string.

  Supports both encrypted and unencrypted private keys in the formats:
  - edsk... (Ed25519 seed or secret key)
  - edesk... (Ed25519 encrypted seed)
  - spsk... (Secp256k1 secret key)
  - spesk... (Secp256k1 encrypted secret key)
  - p2sk... (P256 secret key) 
  - p2esk... (P256 encrypted secret key)
  - BLsk... (BLS12-381 secret key)
  - BLesk... (BLS12-381 encrypted secret key)

  ## Parameters

  - `encoded_key` - Base58-encoded private key string
  - `passphrase` - Passphrase for encrypted keys (optional)

  ## Returns

  - `{:ok, private_key}` - Successfully parsed private key
  - `{:error, reason}` - Parsing failed
  """
  @spec from_encoded_key(String.t(), String.t() | nil) :: {:ok, t()} | {:error, atom()}
  def from_encoded_key(encoded_key, passphrase \\ nil) when is_binary(encoded_key) do
    try do
      {:ok, from_encoded_key!(encoded_key, passphrase)}
    rescue
      e in RuntimeError -> {:error, String.to_atom(e.message)}
      _ -> {:error, :invalid_key}
    end
  end

  @doc """
  Creates a private key from a Tezos encoded key string (raises on error).

  ## Parameters

  - `encoded_key` - Base58-encoded private key string
  - `passphrase` - Passphrase for encrypted keys (optional)

  ## Returns

  - `private_key` - Successfully parsed private key

  ## Raises

  - `RuntimeError` - When key parsing fails
  """
  @spec from_encoded_key!(String.t(), String.t() | nil) :: t()
  def from_encoded_key!(encoded_key, passphrase \\ nil) when is_binary(encoded_key) do
    encoded_key_bytes = String.to_charlist(encoded_key) |> :erlang.list_to_binary()

    # Parse key format
    curve_prefix = binary_part(encoded_key_bytes, 0, 2)

    curve =
      case curve_prefix do
        "ed" -> :ed25519
        "sp" -> :secp256k1
        "p2" -> :p256
        "BL" -> :bls12_381
        _ -> raise "invalid_curve_prefix"
      end

    # Check if encrypted
    encrypted? =
      case binary_part(encoded_key_bytes, 2, 1) do
        "e" -> true
        _ -> false
      end

    # Check if this is a secret key
    key_type =
      if encrypted? do
        binary_part(encoded_key_bytes, 3, 2)
      else
        binary_part(encoded_key_bytes, 2, 2)
      end

    unless key_type == "sk" do
      raise "not_secret_key"
    end

    # Validate key length
    expected_length =
      if encrypted? do
        88
      else
        case curve do
          # can be 54 (seed) or 98 (full key)
          :ed25519 -> 54
          :secp256k1 -> 54
          :p256 -> 54
          :bls12_381 -> 54
        end
      end

    unless byte_size(encoded_key_bytes) in [expected_length, 98] do
      raise "invalid_key_length"
    end

    # Decode from base58 and strip prefix
    decoded_key =
      try do
        # Use decode58! which includes checksum, then validate and remove it
        decoded_with_prefix_and_checksum = Base58Check.decode58!(encoded_key_bytes)

        # Find the prefix and expected data length from the encoding table
        prefix_info = find_encoding_info(encoded_key)
        prefix_len = byte_size(prefix_info.d_prefix)
        expected_data_len = prefix_info.d_len

        # Validate total length (prefix + data + 4-byte checksum)
        expected_total_len = prefix_len + expected_data_len + 4

        if byte_size(decoded_with_prefix_and_checksum) != expected_total_len do
          raise "invalid_length"
        end

        # Extract prefix + data (without checksum)
        prefix_and_data =
          binary_part(decoded_with_prefix_and_checksum, 0, prefix_len + expected_data_len)

        checksum =
          binary_part(decoded_with_prefix_and_checksum, prefix_len + expected_data_len, 4)

        # Validate checksum
        computed_checksum =
          :crypto.hash(:sha256, :crypto.hash(:sha256, prefix_and_data))
          |> binary_part(0, 4)

        if checksum != computed_checksum do
          raise "invalid_checksum"
        end

        # Strip the prefix to get just the key data
        binary_part(prefix_and_data, prefix_len, expected_data_len)
      rescue
        _ -> raise "invalid_base58"
      end

    # Extract secret key bytes
    secret_key_bytes =
      if encrypted? do
        unless passphrase do
          raise "passphrase_required"
        end

        decrypt_key(decoded_key, passphrase)
      else
        decoded_key
      end

    # Create private key with appropriate curve
    curve_struct =
      case curve do
        :secp256k1 -> KnownCurves.get_curve_by_name(:secp256k1)
        :p256 -> KnownCurves.get_curve_by_name(:p256)
        :ed25519 -> raise "ed25519_not_supported"
        :bls12_381 -> raise "bls12_381_not_supported"
      end

    %PrivateKey{
      secret: secret_key_bytes,
      curve: curve_struct
    }
  end

  # Find encoding information for a given key prefix
  defp find_encoding_info(encoded_key) do
    # Base58 encoding configurations (from Forge module)
    encodings = [
      %{e_prefix: "edsk", e_len: 54, d_prefix: <<13, 15, 58, 7>>, d_len: 32},
      %{e_prefix: "edesk", e_len: 88, d_prefix: <<7, 90, 60, 179, 41>>, d_len: 56},
      %{e_prefix: "spsk", e_len: 54, d_prefix: <<17, 162, 224, 201>>, d_len: 32},
      %{e_prefix: "spesk", e_len: 88, d_prefix: <<9, 237, 241, 174, 150>>, d_len: 56},
      %{e_prefix: "p2sk", e_len: 54, d_prefix: <<16, 81, 238, 189>>, d_len: 32},
      %{e_prefix: "p2esk", e_len: 88, d_prefix: <<9, 48, 57, 115, 171>>, d_len: 56},
      %{e_prefix: "edsk", e_len: 98, d_prefix: <<43, 246, 78, 7>>, d_len: 64},
      %{e_prefix: "BLsk", e_len: 54, d_prefix: <<3, 150, 192, 40>>, d_len: 32},
      %{e_prefix: "BLesk", e_len: 88, d_prefix: <<2, 5, 30, 53, 25>>, d_len: 56}
    ]

    Enum.find(encodings, fn encoding ->
      byte_size(encoded_key) == encoding.e_len and
        String.starts_with?(encoded_key, encoding.e_prefix)
    end) || raise "unsupported_key_format"
  end

  # Decrypt an encrypted private key using PBKDF2 + NaCl secretbox
  defp decrypt_key(encrypted_data, passphrase) do
    # Extract salt (first 8 bytes) and encrypted key (remaining 48 bytes)
    salt = binary_part(encrypted_data, 0, 8)
    encrypted_sk = binary_part(encrypted_data, 8, byte_size(encrypted_data) - 8)

    # Derive encryption key using PBKDF2-HMAC-SHA512
    encryption_key = :crypto.pbkdf2_hmac(:sha512, passphrase, salt, 32768, 32)

    # Decrypt using NaCl secretbox with zero nonce
    # 24 bytes of zeros
    nonce = <<0::192>>

    case NaCl.crypto_secretbox_open(encrypted_sk, nonce, encryption_key) do
      {:ok, decrypted} -> decrypted
      {:error, _} -> raise "decryption_failed"
    end
  end
end
