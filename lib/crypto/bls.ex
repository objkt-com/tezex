defmodule Tezex.Crypto.BLS do
  @moduledoc """
  Pure Elixir BLS12-381 cryptographic operations for Tezos tz4 addresses.

  This module provides BLS functionality:
  - Private key operations (from 32-byte seeds or HKDF key generation)
  - Public key derivation (48-byte compressed G1 format)
  - Message signing and verification with multiple ciphersuites
  - Serialization/deserialization compatible with Tezos formats
  - Support for message augmentation, basic, and proof-of-possession schemes

  Based on the BLS12-381 curve with IETF standard ciphersuites:
  - G2Basic: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_
  - G2MessageAugmentation: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_ (default)
  - G2ProofOfPossession: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
  - MinPk variant (48-byte public keys, 96-byte signatures)
  - Hash-to-curve with SSWU mapping

  Partly ported from pytezos@439bafada8f063f9643c789f6154d4646674d66a
  > pytezos / MIT License / (c) 2020 Baking Bad / (c) 2018 Arthur Breitman

  and

  py_ecc@04151f01f59f902ab932a51e0ca0ebce3883fc51
  > py_ecc / MIT License / (c) (c) 2015 Vitalik Buterin
  """

  alias Tezex.Crypto.BLS.Constants
  alias Tezex.Crypto.BLS.Fr
  alias Tezex.Crypto.BLS.G1
  alias Tezex.Crypto.BLS.G2
  alias Tezex.Crypto.BLS.Pairing

  # Key and signature sizes (bytes)
  @secret_key_size 32
  @public_key_size 48
  @signature_size 96

  # IETF BLS signature ciphersuites
  @ciphersuite_basic "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
  @ciphersuite_aug "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"
  @ciphersuite_pop "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
  @pop_tag "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

  # HKDF key generation salt
  @keygen_salt "BLS-SIG-KEYGEN-SALT-"

  defstruct [:secret_key]

  @type t :: %__MODULE__{secret_key: Fr.t()}
  @type public_key :: binary()
  @type signature :: binary()
  @type ciphersuite :: :basic | :message_augmentation | :proof_of_possession
  @type key_info :: binary()

  @doc """
  Creates a new BLS private key from a 32-byte seed.

  This matches octez-client behavior by using the seed directly as the scalar,
  without any key derivation function.

  ## Examples
      iex> seed = :crypto.strong_rand_bytes(32)
      iex> {:ok, bls} = Tezex.Crypto.BLS.from_seed(seed)
      iex> byte_size(Tezex.Crypto.BLS.Fr.to_bytes(bls.secret_key))
      32
  """
  @spec from_seed(binary()) :: {:ok, t()} | {:error, :invalid_seed}
  def from_seed(seed) when byte_size(seed) == @secret_key_size do
    with {:ok, fr_element} <- Fr.from_bytes(seed),
         false <- Fr.is_zero?(fr_element) do
      {:ok, %__MODULE__{secret_key: fr_element}}
    else
      _ -> {:error, :invalid_seed}
    end
  end

  def from_seed(_), do: {:error, :invalid_seed}

  @doc """
  Generates a BLS private key using HKDF key generation (IETF standard).

  This follows the KeyGen algorithm from the IETF BLS specification.

  ## Parameters
  - `ikm`: Input key material (typically 32+ bytes of entropy)
  - `key_info`: Optional key info for domain separation (default: empty)

  ## Examples
      iex> ikm = :crypto.strong_rand_bytes(32)
      iex> {:ok, bls} = Tezex.Crypto.BLS.key_gen(ikm)
      iex> is_struct(bls, Tezex.Crypto.BLS)
      true
  """
  @spec key_gen(binary(), key_info()) :: {:ok, t()} | {:error, :invalid_ikm}
  def key_gen(ikm, key_info \\ <<>>)

  def key_gen(ikm, key_info) when byte_size(ikm) >= 32 do
    case derive_secret_key(ikm, key_info) do
      {:ok, secret_key} -> {:ok, %__MODULE__{secret_key: secret_key}}
      error -> error
    end
  end

  def key_gen(_, _), do: {:error, :invalid_ikm}

  @doc """
  Creates a BLS private key from a secret exponent (integer or bytes).

  ## Examples
      iex> secret_bytes = :crypto.strong_rand_bytes(32)
      iex> {:ok, bls} = Tezex.Crypto.BLS.from_secret_exponent(secret_bytes)
      iex> byte_size(Tezex.Crypto.BLS.serialize_secret_key(bls))
      32
  """
  @spec from_secret_exponent(binary() | integer()) :: {:ok, t()} | {:error, :invalid_secret}
  def from_secret_exponent(secret) when is_binary(secret) do
    from_seed(secret)
  end

  def from_secret_exponent(secret) when is_integer(secret) and secret > 0 do
    fr_element = Fr.from_integer(secret)

    if Fr.is_zero?(fr_element) do
      {:error, :invalid_secret}
    else
      {:ok, %__MODULE__{secret_key: fr_element}}
    end
  end

  def from_secret_exponent(_), do: {:error, :invalid_secret}

  @doc """
  Derives the BLS public key from the private key.
  Returns a 48-byte compressed G1 point.

  ## Examples
      iex> seed = :crypto.strong_rand_bytes(32)
      iex> {:ok, bls} = Tezex.Crypto.BLS.from_seed(seed)
      iex> pubkey = Tezex.Crypto.BLS.get_public_key(bls)
      iex> byte_size(pubkey)
      48
  """
  @spec get_public_key(t()) :: public_key()
  def get_public_key(%__MODULE__{secret_key: secret_key}) do
    # Multiply the G1 generator by the private key scalar
    generator = G1.generator()
    public_key_point = G1.mul(generator, secret_key)

    # Compress to 48-byte format
    G1.to_compressed_bytes(public_key_point)
  end

  @doc """
  Signs a message with the BLS private key using the specified ciphersuite.
  Returns a 96-byte signature.

  ## Ciphersuites
  - `:message_augmentation` (default): Message augmented with public key (most secure)
  - `:basic`: Basic BLS signature (requires message uniqueness for aggregation)
  - `:proof_of_possession`: Proof-of-possession scheme

  ## Examples
      iex> seed = :crypto.strong_rand_bytes(32)
      iex> {:ok, bls} = Tezex.Crypto.BLS.from_seed(seed)
      iex> message = "test message"
      iex> signature = Tezex.Crypto.BLS.sign(bls, message)
      iex> byte_size(signature)
      96
  """
  @spec sign(t(), binary(), ciphersuite()) :: signature()
  def sign(bls_key, message, ciphersuite \\ :message_augmentation)

  def sign(%__MODULE__{secret_key: secret_key}, message, :message_augmentation)
      when is_binary(message) do
    public_key = get_public_key(%__MODULE__{secret_key: secret_key})
    augmented_message = public_key <> message
    h_point = G2.hash_to_curve(augmented_message, @ciphersuite_aug)
    signature_point = G2.mul(h_point, secret_key)
    G2.to_compressed_bytes(signature_point)
  end

  def sign(%__MODULE__{secret_key: secret_key}, message, :basic) when is_binary(message) do
    h_point = G2.hash_to_curve(message, @ciphersuite_basic)
    signature_point = G2.mul(h_point, secret_key)
    G2.to_compressed_bytes(signature_point)
  end

  def sign(%__MODULE__{secret_key: secret_key}, message, :proof_of_possession)
      when is_binary(message) do
    h_point = G2.hash_to_curve(message, @ciphersuite_pop)
    signature_point = G2.mul(h_point, secret_key)
    G2.to_compressed_bytes(signature_point)
  end

  @doc """
  Verifies a BLS signature against a message and public key using the specified ciphersuite.

  ## Ciphersuites
  - `:message_augmentation` (default): Message augmented with public key
  - `:basic`: Basic BLS signature
  - `:proof_of_possession`: Proof-of-possession scheme

  ## Examples
      iex> seed = :crypto.strong_rand_bytes(32)
      iex> {:ok, bls} = Tezex.Crypto.BLS.from_seed(seed)
      iex> message = "test message"
      iex> pubkey = Tezex.Crypto.BLS.get_public_key(bls)
      iex> signature = Tezex.Crypto.BLS.sign(bls, message)
      iex> Tezex.Crypto.BLS.verify(signature, message, pubkey)
      true
  """
  @spec verify(signature(), binary(), public_key(), ciphersuite()) :: boolean()
  def verify(signature, message, public_key, ciphersuite \\ :message_augmentation)

  def verify(signature, message, public_key, ciphersuite)
      when byte_size(signature) == @signature_size and
             byte_size(public_key) == @public_key_size and
             is_binary(message) do
    with true <- is_valid_bls_signature_format?(signature),
         true <- is_valid_bls_pubkey_format?(public_key) do
      case ciphersuite do
        :message_augmentation ->
          augmented_message = public_key <> message
          verify_signature(signature, augmented_message, public_key, @ciphersuite_aug)

        :basic ->
          verify_signature(signature, message, public_key, @ciphersuite_basic)

        :proof_of_possession ->
          verify_signature(signature, message, public_key, @ciphersuite_pop)
      end
    else
      _ -> false
    end
  end

  def verify(_, _, _, _), do: false

  # Check if the signature has valid BLS format (compressed G2 point).
  # Infinity points are allowed for signatures.
  defp is_valid_bls_signature_format?(signature) when byte_size(signature) == 96 do
    <<z1::binary-size(48), z2::binary-size(48)>> = signature

    # Check z1 (first component) compression flags by pattern matching on bits
    # C B A _ _ _ _ _
    # │ │ │
    # │ │ └─ sign/lexicographic flag (bit 5)
    # │ └─── infinity flag (bit 6)
    # └───── compression flag (bit 7)
    <<c_flag::size(1), b_flag::size(1), a_flag::size(1), _::size(5), _rest::binary-size(47)>> = z1

    # bits 7,6,5 must be 0
    z2_no_flags = match?(<<0::size(3), _::size(5), _::binary-size(47)>>, z2)

    # compression must be enabled, z2 must have no flags
    if c_flag == 1 and z2_no_flags do
      # If infinity point, validate format: z1=0xC0+zeros, z2=zeros
      if b_flag == 1 do
        # Infinity signature: must have a_flag=0 and exact pattern
        a_flag == 0 and signature == <<0xC0, 0::size(760)>>
      else
        # Non-infinity point: try to decompress and validate
        case G2.from_compressed_bytes(signature) do
          {:ok, point} -> G2.is_on_curve?(point) and not G2.is_infinity?(point)
          {:error, _} -> false
        end
      end
    else
      false
    end
  end

  defp is_valid_bls_signature_format?(_), do: false

  # Check if the public key has valid BLS format (compressed G1 point).
  # Infinity points are rejected for public keys.
  defp is_valid_bls_pubkey_format?(pubkey) when byte_size(pubkey) == 48 do
    # Extract compression flags by pattern matching on bits
    # C B A _ _ _ _ _
    # │ │ │
    # │ │ └─ sign/lexicographic flag (bit 5)
    # │ └─── infinity flag (bit 6)
    # └───── compression flag (bit 7)
    <<c_flag::size(1), b_flag::size(1), _a_flag::size(1), _::size(5), _rest::binary-size(47)>> =
      pubkey

    # c_flag must be 1
    if c_flag == 1 do
      # Infinity points are rejected for public keys
      if b_flag == 1 do
        # Reject infinity public keys
        false
      else
        # Try to decompress and validate the point
        case G1.from_compressed_bytes(pubkey) do
          {:ok, point} -> G1.is_on_curve?(point) and not G1.is_infinity?(point)
          {:error, _} -> false
        end
      end
    else
      false
    end
  end

  defp is_valid_bls_pubkey_format?(_), do: false

  defp verify_signature(signature, message, public_key, ciphersuite) do
    # This implements cryptographically secure BLS signature verification
    # using the full BLS12-381 pairing implementation

    with {:ok, pubkey_point} <- G1.from_compressed_bytes(public_key),
         {:ok, signature_point} <- G2.from_compressed_bytes(signature),
         false <- G1.is_infinity?(pubkey_point),
         false <- G2.is_infinity?(signature_point) do
      # Hash the message to G2
      message_point = G2.hash_to_curve(message, ciphersuite)

      g1_generator = G1.generator()
      Pairing.pairing_check(pubkey_point, message_point, g1_generator, signature_point)
    else
      _ -> false
    end
  end

  @doc """
  Deserializes a BLS private key from bytes.
  """
  @spec deserialize_secret_key(binary()) :: {:ok, t()} | {:error, :invalid_key}
  def deserialize_secret_key(secret_bytes) do
    case from_seed(secret_bytes) do
      {:ok, bls_key} when byte_size(secret_bytes) == @secret_key_size -> {:ok, bls_key}
      _ -> {:error, :invalid_key}
    end
  end

  @doc """
  Serializes a BLS private key to bytes.
  """
  @spec serialize_secret_key(t()) :: binary()
  def serialize_secret_key(%__MODULE__{secret_key: secret_key}) do
    Fr.to_bytes(secret_key)
  end

  @doc """
  Returns the expected sizes for BLS keys and signatures.
  """
  @spec sizes() :: %{
          secret_key: pos_integer(),
          public_key: pos_integer(),
          signature: pos_integer()
        }
  def sizes do
    %{
      secret_key: @secret_key_size,
      public_key: @public_key_size,
      signature: @signature_size
    }
  end

  @doc """
  Converts a hex string to binary, handling both uppercase and lowercase.
  """
  @spec from_hex(String.t()) :: {:ok, binary()} | {:error, :invalid_hex}
  def from_hex(hex_string) when is_binary(hex_string) do
    case Base.decode16(hex_string, case: :mixed) do
      {:ok, binary} -> {:ok, binary}
      :error -> {:error, :invalid_hex}
    end
  end

  @doc """
  Converts binary to hex string (lowercase).
  """
  @spec to_hex(binary()) :: String.t()
  def to_hex(binary) when is_binary(binary) do
    Base.encode16(binary, case: :lower)
  end

  @doc """
  Generates a proof-of-possession for a BLS public key.

  This proves that the holder knows the corresponding private key,
  following the IETF BLS proof-of-possession specification.
  """
  @spec pop_prove(t()) :: signature()
  def pop_prove(%__MODULE__{secret_key: secret_key}) do
    public_key = get_public_key(%__MODULE__{secret_key: secret_key})
    h_point = G2.hash_to_curve(public_key, @pop_tag)
    signature_point = G2.mul(h_point, secret_key)
    G2.to_compressed_bytes(signature_point)
  end

  @doc """
  Verifies a proof-of-possession for a BLS public key.
  """
  @spec pop_verify(public_key(), signature()) :: boolean()
  def pop_verify(public_key, proof_of_possession)
      when byte_size(public_key) == @public_key_size and
             byte_size(proof_of_possession) == @signature_size do
    with true <- is_valid_bls_signature_format?(proof_of_possession),
         true <- is_valid_bls_pubkey_format?(public_key) do
      verify_signature(proof_of_possession, public_key, public_key, @pop_tag)
    else
      _ -> false
    end
  end

  def pop_verify(_, _), do: false

  @doc """
  Returns the supported BLS ciphersuites and their domain separation tags.
  """
  @spec ciphersuites() :: %{
          basic: String.t(),
          message_augmentation: String.t(),
          proof_of_possession: String.t(),
          pop_tag: String.t()
        }
  def ciphersuites do
    %{
      basic: @ciphersuite_basic,
      message_augmentation: @ciphersuite_aug,
      proof_of_possession: @ciphersuite_pop,
      pop_tag: @pop_tag
    }
  end

  @doc """
  Validates a BLS public key to ensure it's a valid G1 point.
  Infinity points are rejected for public keys .
  """
  @spec validate_public_key(public_key()) :: boolean()
  def validate_public_key(public_key) when byte_size(public_key) == @public_key_size do
    is_valid_bls_pubkey_format?(public_key)
  end

  def validate_public_key(_), do: false

  @doc """
  Validates a BLS signature to ensure it's a valid G2 point.
  Infinity points are allowed for signatures (unlike public keys).
  """
  @spec validate_signature(signature()) :: boolean()
  def validate_signature(signature) when byte_size(signature) == @signature_size do
    is_valid_bls_signature_format?(signature)
  end

  def validate_signature(_), do: false

  # Private helper functions

  defp derive_secret_key(ikm, key_info) do
    # IETF BLS KeyGen algorithm using HKDF

    salt = @keygen_salt
    secret_key_int = derive_key_with_hkdf(ikm, salt, key_info, 0)
    fr_element = Fr.from_integer(secret_key_int)

    if Fr.is_zero?(fr_element) do
      derive_key_retry(ikm, salt, key_info, 1)
    else
      {:ok, fr_element}
    end
  end

  defp derive_key_retry(ikm, base_salt, key_info, iteration) when iteration < 256 do
    # Update salt and try again (following IETF spec)
    salt = :crypto.hash(:sha256, base_salt <> <<iteration>>)
    secret_key_int = derive_key_with_hkdf(ikm, salt, key_info, iteration)
    fr_element = Fr.from_integer(secret_key_int)

    if Fr.is_zero?(fr_element) do
      derive_key_retry(ikm, base_salt, key_info, iteration + 1)
    else
      {:ok, fr_element}
    end
  end

  defp derive_key_retry(_, _, _, _), do: {:error, :key_generation_failed}

  defp derive_key_with_hkdf(ikm, salt, key_info, _iteration) do
    # HKDF-based key derivation compatible with py_ecc
    # ceil((1.5 * ceil(log2(curve_order))) / 8)
    l = 48

    # HKDF Extract
    prk = :crypto.mac(:hmac, :sha256, salt, ikm <> <<0>>)

    # HKDF Expand
    info = key_info <> <<l::16>>
    okm = hkdf_expand(prk, info, l)

    # Convert to integer mod curve order
    integer_from_bytes(okm) |> rem(Constants.curve_order())
  end

  defp hkdf_expand(prk, info, length) do
    # HKDF Expand implementation
    # ceil(length / 32)
    n = div(length + 31, 32)

    0..(n - 1)
    |> Enum.reduce(<<>>, fn i, acc ->
      t_prev = if i == 0, do: <<>>, else: binary_part(acc, byte_size(acc) - 32, 32)
      t_i = :crypto.mac(:hmac, :sha256, prk, t_prev <> info <> <<i + 1>>)
      acc <> t_i
    end)
    |> binary_part(0, length)
  end

  defp integer_from_bytes(bytes) do
    # Convert bytes to integer (big-endian)
    bytes
    |> :binary.bin_to_list()
    |> Enum.reduce(0, fn byte, acc -> acc * 256 + byte end)
  end
end
