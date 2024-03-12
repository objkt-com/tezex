defmodule Tezex.Crypto do
  @moduledoc """
  A set of functions to check Tezos signed messages, derive a pkh from a pubkey, verify that a public key corresponds to a wallet address (public key hash).
  """
  alias Tezex.Crypto.{Base58Check, ECDSA, Signature}

  @prefixes %{
    eddsa: <<43, 246, 78, 7>>
  }
  @prefixes_sig %{
    eddsa: <<4, 130, 43>>
  }

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
      {:error, :invalid_pubkey_format}
  """
  @spec check_signature(binary, binary, binary, binary) ::
          :ok | {:error, :address_mismatch | :invalid_pubkey_format | :bad_signature}

  def check_signature("tz" <> _ = address, signature, message, pubkey) do
    with :ok <- check_address(address, pubkey),
         true <- verify_signature(signature, message, pubkey) do
      :ok
    else
      false -> {:error, :bad_signature}
      {:error, err} -> {:error, err}
    end
  end

  @doc """
  Verify that `signature` is a valid signature for `message` signed with the private key corresponding to public key `pubkey`
  """
  @spec verify_signature(binary, binary, binary) :: boolean
  def verify_signature("ed" <> _ = signature, message, pubkey) do
    # tz1…
    message_hash = hash_message(message)
    signature = decode_signature(signature)

    # <<0x0D, 0x0F, 0x25, 0xD9>>
    <<13, 15, 37, 217, public_key::binary-size(32)>> <> _ = Base58Check.decode58!(pubkey)

    :crypto.verify(:eddsa, :none, message_hash, signature, [public_key, :ed25519])
  end

  def verify_signature("sp" <> _ = signature, msg, pubkey) do
    # tz2…
    <<r::unsigned-integer-size(256), s::unsigned-integer-size(256)>> = decode_signature(signature)
    signature = %Signature{r: r, s: s}

    message = :binary.decode_hex(msg)

    # <<0x03, 0xFE, 0xE2, 0x56>>
    <<3, 254, 226, 86, public_key::binary-size(33)>> <> _ = Base58Check.decode58!(pubkey)

    public_key = ECDSA.decode_public_key(public_key, :secp256k1)

    ECDSA.verify?(message, signature, public_key, hashfunc: fn msg -> Blake2.hash2b(msg, 32) end)
  end

  def verify_signature("p2" <> _ = signature, msg, pubkey) do
    # tz3…
    <<54, 240, 44, 52, sig::binary-size(64)>> <> _ = Base58Check.decode58!(signature)

    <<r::unsigned-integer-size(256), s::unsigned-integer-size(256)>> = sig
    signature = %Signature{r: r, s: s}

    message = :binary.decode_hex(msg)

    # <<0x03, 0xB2, 0x8B, 0x7F>>
    <<3, 178, 139, 127, public_key::binary-size(33)>> <> _ = Base58Check.decode58!(pubkey)

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
      {:ok, ^address} ->
        :ok

      {:ok, _derived} ->
        {:error, :address_mismatch}

      err ->
        err
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
      {:ok, <<13, 15, 37, 217, public_key::binary-size(32)>> <> _} ->
        pkh = <<6, 161, 159>>
        derive_address(public_key, pkh)

      # tz2 addresses: "sppk" <> _
      {:ok, <<3, 254, 226, 86, public_key::binary-size(33)>> <> _} ->
        pkh = <<6, 161, 161>>
        derive_address(public_key, pkh)

      # tz3 addresses: "p2pk" <> _
      {:ok, <<3, 178, 139, 127, public_key::binary-size(33)>> <> _} ->
        pkh = <<6, 161, 164>>
        derive_address(public_key, pkh)

      _ ->
        {:error, :invalid_pubkey_format}
    end
  end

  defp derive_address(pubkey, pkh) do
    derived =
      Blake2.hash2b(pubkey, 20)
      |> Tezex.Crypto.Base58Check.encode(pkh)

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
        "tz1" <> _ -> <<13, 15, 37, 217>>
        "tz2" <> _ -> <<3, 254, 226, 86>>
        "tz3" <> _ -> <<3, 178, 139, 127>>
        _ -> :error
      end

    with prefix when is_binary(prefix) <- prefix,
         {:ok, bin_pubkey} <- Base.decode16(String.upcase(hex_pubkey)) do
      {:ok, Tezex.Crypto.Base58Check.encode(bin_pubkey, prefix)}
    end
  end

  defp decode_privkey("edsk" <> _ = key) do
    key = Base58Check.decode58!(key)
    binary_part(key, byte_size(@prefixes.eddsa), 32)
  end

  def sign("edsk" <> _ = secret_key, bytes, watermark \\ <<>>) do
    msg = watermark <> :binary.decode_hex(bytes)
    bytes_hash = Blake2.hash2b(msg, 32)
    decoded_key = decode_privkey(secret_key)
    signature = :crypto.sign(:eddsa, :none, bytes_hash, [decoded_key, :ed25519])
    Base58Check.encode(signature, @prefixes_sig.eddsa)
  end

  defp decode_signature(data) do
    data
    |> Base58Check.decode58!()
    |> binary_part(5, 64)
  end

  defp hash_message(message) do
    iodata = :binary.decode_hex(message)

    case Blake2.hash2b(iodata, 32) do
      :error -> ""
      bin -> bin
    end
  end
end
