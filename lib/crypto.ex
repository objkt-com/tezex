defmodule Tezex.Crypto do
  @moduledoc """
  A set of functions to check Tezos signed messages, derive a pkh from a pubkey, verify that a public key corresponds to a wallet address (public key hash).
  """

  alias Tezex.Crypto.Base58Check
  alias Tezex.Crypto.ECDSA
  alias Tezex.Crypto.KnownCurves
  alias Tezex.Crypto.PrivateKey
  alias Tezex.Crypto.Signature
  alias Tezex.Crypto.Utils
  alias Tezex.Micheline

  # public key
  @prefix_edpk <<13, 15, 37, 217>>
  @prefix_sppk <<3, 254, 226, 86>>
  @prefix_p2pk <<3, 178, 139, 127>>
  # public key hash
  @prefix_tz1 <<6, 161, 159>>
  @prefix_tz2 <<6, 161, 161>>
  @prefix_tz3 <<6, 161, 164>>
  # private key
  @prefix_edsk <<43, 246, 78, 7>>
  @prefix_spsk <<17, 162, 224, 201>>
  @prefix_p2sk <<16, 81, 238, 189>>
  # sig
  @prefix_edsig <<9, 245, 205, 134, 18>>
  @prefix_spsig <<13, 115, 101, 19, 63>>
  @prefix_p2sig <<54, 240, 44, 52>>
  @prefix_sig <<4, 130, 43>>

  @type privkey_param :: binary() | {privkey :: binary(), passphrase :: binary()}

  @doc """
  Verify that `address` is the public key hash of `pubkey` and that `signature` is a valid signature for `message` signed with the private key corresponding to public key `pubkey`.

  ## Examples
      iex> address = "tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx"
      iex> address_b = "tz1burnburnburnburnburnburnburjAYjjX"
      iex> signature = "spsig1ZNQaUKNERZSiEiNviqa5EAPkcNASXhfkXtxRatZTDZAnUB4Ra2Jus8b1oEpFnPx8Z6g28pd8vK3R8nPK29JDU5FiSLH5T"
      iex> message = "05010000007154657a6f73205369676e6564204d6573736167653a207369676e206d6520696e20617320747a32424338337076454161673672325a56376b5067684e41626a466f69716843765a78206f6e206f626a6b742e636f6d20617420323032312d31302d30345431383a35393a31332e3939305a"
      iex> public_key = "sppk7aBerAEA6tv4wzg6FnK7i5YrGtEGFVvNjWhc2QX8bhzpouBVFSW"
      iex> Tezex.Crypto.check_signature(address, signature, message, public_key)
      :ok
      iex> Tezex.Crypto.check_signature(address_b, signature, message, public_key)
      {:error, :address_mismatch}
      iex> Tezex.Crypto.check_signature(address, signature, "", public_key)
      {:error, :bad_signature}
      iex> Tezex.Crypto.check_signature(address, "x" <> signature, "", public_key)
      {:error, :invalid_signature}
  """
  @spec check_signature(binary, binary, binary, binary) ::
          :ok
          | {:error,
             :address_mismatch | :invalid_pubkey_format | :invalid_signature | :bad_signature}

  def check_signature("tz" <> _ = address, signature, message, pubkey) do
    with :ok <- check_address(address, pubkey),
         {:ok, _} <- extract_pubkey(pubkey),
         {:ok, _} <- decode_signature(signature),
         true <- verify_signature(signature, message, pubkey) do
      :ok
    else
      false -> {:error, :bad_signature}
      {:error, err} -> {:error, err}
    end
  end

  def extract_pubkey(pubkey) do
    case Base58Check.decode58(pubkey) do
      {:ok, <<@prefix_edpk, public_key::binary-size(32)>> <> _} -> {:ok, public_key}
      {:ok, <<@prefix_sppk, public_key::binary-size(33)>> <> _} -> {:ok, public_key}
      {:ok, <<@prefix_p2pk, public_key::binary-size(33)>> <> _} -> {:ok, public_key}
      _ -> {:error, :invalid_pubkey_format}
    end
  end

  @doc """
  Verify that `signature` is a valid signature for `message` signed with the private key corresponding to public key `pubkey`
  """
  @spec verify_signature(binary, binary, binary) :: boolean()
  def verify_signature(signature, message, "ed" <> _ = pubkey) do
    # tz1…
    message_hash = hash_message(message)
    {:ok, signature} = decode_signature(signature)
    {:ok, public_key} = extract_pubkey(pubkey)

    :crypto.verify(:eddsa, :none, message_hash, signature, [public_key, :ed25519])
  end

  def verify_signature(signature, msg, "sp" <> _ = pubkey) do
    # tz2…
    message = :binary.decode_hex(msg)

    {:ok, <<r::unsigned-integer-size(256), s::unsigned-integer-size(256)>>} =
      decode_signature(signature)

    signature = %Signature{r: r, s: s}

    {:ok, public_key} = extract_pubkey(pubkey)
    public_key = ECDSA.decode_public_key(public_key, :secp256k1)

    ECDSA.verify?(message, signature, public_key, hashfunc: fn msg -> Blake2.hash2b(msg, 32) end)
  end

  def verify_signature(signature, msg, "p2" <> _ = pubkey) do
    # tz3…
    message = :binary.decode_hex(msg)
    {:ok, sig} = decode_signature(signature)

    <<r::unsigned-integer-size(256), s::unsigned-integer-size(256)>> = sig
    signature = %Signature{r: r, s: s}

    {:ok, public_key} = extract_pubkey(pubkey)
    public_key = ECDSA.decode_public_key(public_key, :prime256v1)

    ECDSA.verify?(message, signature, public_key, hashfunc: fn msg -> Blake2.hash2b(msg, 32) end)
  end

  def verify_signature(_, _, _) do
    {:error, :invalid_pubkey_format}
  end

  @doc """
  Verify that `address` is the public key hash of `pubkey`.

  ## Examples
      iex> pubkey = "sppk7aBerAEA6tv4wzg6FnK7i5YrGtEGFVvNjWhc2QX8bhzpouBVFSW"
      iex> Tezex.Crypto.check_address("tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx", pubkey)
      :ok
      iex> Tezex.Crypto.check_address("tz1burnburnburnburnburnburnburjAYjjX", pubkey)
      {:error, :address_mismatch}
      iex> Tezex.Crypto.check_address("tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx", "x" <> pubkey)
      {:error, :invalid_pubkey_format}
  """
  @spec check_address(nonempty_binary, nonempty_binary) ::
          :ok | {:error, :address_mismatch | :invalid_pubkey_format}
  def check_address(address, pubkey) do
    case derive_address(pubkey) do
      {:ok, ^address} -> :ok
      {:ok, _derived} -> {:error, :address_mismatch}
      err -> err
    end
  end

  @doc """
  Derive public key hash (Tezos wallet address) from public key

  ## Examples
      iex> Tezex.Crypto.derive_address("edpktsPhZ8weLEXqf4Fo5FS9Qx8ZuX4QpEBEwe63L747G8iDjTAF6w")
      {:ok, "tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z"}
      iex> Tezex.Crypto.derive_address("sppk7aBerAEA6tv4wzg6FnK7i5YrGtEGFVvNjWhc2QX8bhzpouBVFSW")
      {:ok, "tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx"}
      iex> Tezex.Crypto.derive_address("p2pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa")
      {:ok, "tz3bPFa6mGv8m4Ppn7w5KSDyAbEPwbJNpC9p"}
      iex> Tezex.Crypto.derive_address("_p2pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa")
      {:error, :invalid_pubkey_format}
      iex> Tezex.Crypto.derive_address("p2pk65yRxCX65k6")
      {:error, :invalid_pubkey_format}
  """
  @spec derive_address(nonempty_binary) ::
          {:ok, nonempty_binary} | {:error, :invalid_pubkey_format}
  def derive_address(pubkey) do
    case Base58Check.decode58(pubkey) do
      # tz1 addresses: "edpk" <> _
      {:ok, <<@prefix_edpk, public_key::binary-size(32)>> <> _} ->
        derive_address(public_key, @prefix_tz1)

      # tz2 addresses: "sppk" <> _
      {:ok, <<@prefix_sppk, public_key::binary-size(33)>> <> _} ->
        derive_address(public_key, @prefix_tz2)

      # tz3 addresses: "p2pk" <> _
      {:ok, <<@prefix_p2pk, public_key::binary-size(33)>> <> _} ->
        derive_address(public_key, @prefix_tz3)

      _ ->
        {:error, :invalid_pubkey_format}
    end
  end

  defp derive_address(pubkey, pkh) do
    derived =
      Blake2.hash2b(pubkey, 20)
      |> Base58Check.encode(pkh)

    {:ok, derived}
  end

  @doc """
  Encode a raw public key

  ## Examples
      iex> Tezex.Crypto.encode_pubkey("tz1LPggcEZincSDQJUXrskwJPif4aJhWxMjd", "52d396892b2489ec91406f83680b172b5ca42f606128cd4c44ea4d09d31aa524")
      {:ok, "edpkuGhdSSNgqT92Gwoxt9vV3TmpQE93TtQSn5kkyULCh7cfeQFTno"}
      iex> Tezex.Crypto.encode_pubkey("tz1LPggcEZincSDQJUXrskwJPif4aJhWxMjd", "foo")
      :error
  """
  @spec encode_pubkey(nonempty_binary, nonempty_binary) :: :error | {:ok, nonempty_binary}
  def encode_pubkey(pkh, hex_pubkey) do
    prefix =
      case pkh do
        "tz1" <> _ -> @prefix_edpk
        "tz2" <> _ -> @prefix_sppk
        "tz3" <> _ -> @prefix_p2pk
        _ -> :error
      end

    with prefix when is_binary(prefix) <- prefix,
         {:ok, bin_pubkey} <- Base.decode16(String.upcase(hex_pubkey)) do
      {:ok, Base58Check.encode(bin_pubkey, prefix)}
    end
  end

  defp decode_privkey({privkey, passphrase}) do
    throw("not implemented")
    decode_privkey(privkey, passphrase)
  end

  defp decode_privkey(privkey, passphrase \\ nil) do
    if binary_part(privkey, 2, 1) == "e" and is_nil(passphrase) do
      throw("missing passphrase")
    end

    prefix =
      case privkey do
        "edsk" <> _ -> @prefix_edsk
        "edes" <> _ -> @prefix_edsk
        "spsk" <> _ -> @prefix_spsk
        "spes" <> _ -> @prefix_spsk
        "p2sk" <> _ -> @prefix_p2sk
        "p2es" <> _ -> @prefix_p2sk
      end

    decoded_privkey =
      Base58Check.decode58!(privkey)
      |> binary_part(byte_size(prefix), 32)
      |> Utils.pad(32, :leading)

    {privkey, decoded_privkey}
  end

  @doc """
  Sign an operation using `0x03` as watermark
  """
  @spec sign_operation(privkey_param(), binary()) :: nonempty_binary()
  def sign_operation(privkey_param, bytes) do
    sign(privkey_param, bytes, <<3>>)
  end

  @doc """
  Sign the hexadecimal/Micheline representation of a string, Micheline encoding is done when `bytes` do not start with `"0501"`.

  ## Examples
      iex> encoded_private_key = "spsk24EJohZHJkZnWEzj3w9wE7BFARpFmq5WAo9oTtqjdJ2t4pyoB3"
      iex> Tezex.Crypto.sign_message(encoded_private_key, "foo")
      "sigm9uJiGjdk2DpuqTmHcjzpAdTSQfqKxFuDKodyNT8JP3UvrfoPFTNkFbFgDP1WfAi2PjJ3dcpZFLTagD7gUBmwVWbPr5mk"
      iex> msg = Tezex.Micheline.pack("foo", :string)
      "050100000003666f6f"
      iex> Tezex.Crypto.sign_message(encoded_private_key, msg)
      "sigm9uJiGjdk2DpuqTmHcjzpAdTSQfqKxFuDKodyNT8JP3UvrfoPFTNkFbFgDP1WfAi2PjJ3dcpZFLTagD7gUBmwVWbPr5mk"
  """
  @spec sign_message(privkey_param(), binary()) :: nonempty_binary()
  def sign_message(privkey_param, "0501" <> _ = bytes) do
    sign(privkey_param, bytes)
  end

  def sign_message(privkey_param, bytes) do
    sign(privkey_param, Micheline.pack(bytes, :string))
  end

  @spec sign(privkey_param(), binary(), binary()) :: nonempty_binary()
  @spec sign(privkey_param(), binary()) :: nonempty_binary()
  def sign(privkey_param, bytes, watermark \\ <<>>) do
    msg = :binary.decode_hex(bytes)
    {privkey, decoded_key} = decode_privkey(privkey_param)

    case privkey do
      "ed" <> _ ->
        bytes_hash = Blake2.hash2b(watermark <> msg, 32)
        signature = :crypto.sign(:eddsa, :none, bytes_hash, [decoded_key, :ed25519])
        Base58Check.encode(signature, @prefix_sig)

      "sp" <> _ ->
        pk = %PrivateKey{secret: decoded_key, curve: KnownCurves.secp256k1()}
        s = ECDSA.sign(watermark <> msg, pk, hashfunc: fn msg -> Blake2.hash2b(msg, 32) end)

        r_bin = Integer.to_string(s.r, 16)
        s_bin = Integer.to_string(s.s, 16)

        r_bin = Utils.pad(r_bin, 64, :leading)
        s_bin = Utils.pad(s_bin, 64, :leading)

        signature = :binary.decode_hex(r_bin <> s_bin)

        Base58Check.encode(signature, @prefix_sig)

      "p2" <> _ ->
        pk = %PrivateKey{secret: decoded_key, curve: KnownCurves.prime256v1()}
        s = ECDSA.sign(watermark <> msg, pk, hashfunc: fn msg -> Blake2.hash2b(msg, 32) end)

        r_bin = Integer.to_string(s.r, 16)
        s_bin = Integer.to_string(s.s, 16)

        r_bin = Utils.pad(r_bin, 64, :leading)
        s_bin = Utils.pad(s_bin, 64, :leading)

        signature = :binary.decode_hex(r_bin <> s_bin)

        Base58Check.encode(signature, @prefix_sig)
    end
  end

  @spec decode_signature(binary()) :: {:error, :invalid_signature} | {:ok, binary()}
  defp decode_signature("edsig" <> _ = sig) do
    case Base58Check.decode58(sig) do
      {:ok, <<@prefix_edsig, sig::binary-size(64)>> <> _} -> {:ok, sig}
      _ -> {:error, :invalid_signature}
    end
  end

  defp decode_signature("spsig" <> _ = sig) do
    case Base58Check.decode58(sig) do
      {:ok, <<@prefix_spsig, sig::binary-size(64)>> <> _} -> {:ok, sig}
      _ -> {:error, :invalid_signature}
    end
  end

  defp decode_signature("p2sig" <> _ = sig) do
    case Base58Check.decode58(sig) do
      {:ok, <<@prefix_p2sig, sig::binary-size(64)>> <> _} -> {:ok, sig}
      _ -> {:error, :invalid_signature}
    end
  end

  defp decode_signature("sig" <> _ = sig) do
    case Base58Check.decode58(sig) do
      {:ok, <<@prefix_sig, sig::binary-size(64)>> <> _} -> {:ok, sig}
      _ -> {:error, :invalid_signature}
    end
  end

  defp decode_signature(_) do
    {:error, :invalid_signature}
  end

  defp hash_message(message) do
    iodata = :binary.decode_hex(message)

    case Blake2.hash2b(iodata, 32) do
      :error -> ""
      bin -> bin
    end
  end
end
