defmodule Tezex.Crypto do
  @moduledoc """
  A set of functions to check Tezos signed messages and verify a public key corresponds to a wallet address (public key hash).
  """
  alias Tezex.Crypto.{Base58Check, ECDSA, Signature}

  @doc """
  Verify that `address` is the public key hash of `pubkey` and that `signature` is a valid signature for `message` signed with the private key corresponding to public key `pubkey`.

  ## Examples
      iex> address = "tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx"
      iex> address_b = "tz1burnburnburnburnburnburnburjAYjjX"
      iex> signature = "spsig1ZNQaUKNERZSiEiNviqa5EAPkcNASXhfkXtxRatZTDZAnUB4Ra2Jus8b1oEpFnPx8Z6g28pd8vK3R8nPK29JDU5FiSLH5T"
      iex> message = "05010000007154657a6f73205369676e6564204d6573736167653a207369676e206d6520696e20617320747a32424338337076454161673672325a56376b5067684e41626a466f69716843765a78206f6e206f626a6b742e636f6d20617420323032312d31302d30345431383a35393a31332e3939305a"
      iex> public_key = "sppk7aBerAEA6tv4wzg6FnK7i5YrGtEGFVvNjWhc2QX8bhzpouBVFSW"
      iex> Tezex.Crypto.check_signature(address, signature, message, public_key)
      true
      iex> Tezex.Crypto.check_signature(address_b, signature, message, public_key)
      false
      iex> Tezex.Crypto.check_signature(address, signature, "", public_key)
      false
  """
  @spec check_signature(binary, binary, binary, binary) :: boolean
  def check_signature("tz" <> _ = address, signature, message, pubkey) do
    with :ok <- check_address(address, pubkey),
         true <- verify_signature(signature, message, pubkey) do
      true
    else
      _ -> false
    end
  end

  defp decode_signature(data) do
    data
    |> decode_base58()
    |> binary_part(5, 64)
  end

  defp decode_base58(data) do
    Base58Check.decode58!(data)
  end

  defp hash_message(message) do
    try do
      iodata = :binary.decode_hex(message)
      :enacl.generichash(32, iodata)
    rescue
      ArgumentError -> ""
    end
  end

  @doc """
  Verify that `signature` is a valid signature for `message` signed with the private key corresponding to public key `pubkey`
  """
  @spec verify_signature(binary, binary, binary) :: boolean
  def verify_signature("ed" <> _sig = signature, message, pubkey) do
    # tz1…
    message_hash = hash_message(message)
    signature = decode_signature(signature)

    try do
      pubkey =
        pubkey
        |> decode_base58()
        |> binary_part(4, 32)

      :enacl.sign_verify_detached(signature, message_hash, pubkey)
    rescue
      ArgumentError -> false
    end
  end

  def verify_signature("sp" <> _sig = signature, msg, pubkey) do
    # tz2…
    sig = decode_signature(signature)

    <<r::unsigned-integer-size(256), s::unsigned-integer-size(256)>> = sig
    signature = %Signature{r: r, s: s}

    message = :binary.decode_hex(msg)

    # <<0x03, 0xFE, 0xE2, 0x56>>
    <<3, 254, 226, 86>> <> <<public_key::binary-size(33)>> <> _ = decode_base58(pubkey)

    public_key = ECDSA.decode_public_key(public_key, :secp256k1)

    ECDSA.verify?(message, signature, public_key,
      hashfunc: fn msg -> :enacl.generichash(32, msg) end
    )
  end

  def verify_signature("p2" <> _sig = signature, msg, pubkey) do
    # tz3…
    <<54, 240, 44, 52>> <> <<sig::binary-size(64)>> <> _ = decode_base58(signature)

    <<r::unsigned-integer-size(256), s::unsigned-integer-size(256)>> = sig
    signature = %Signature{r: r, s: s}

    message = :binary.decode_hex(msg)

    # <<0x03, 0xB2, 0x8B, 0x7F>>
    <<3, 178, 139, 127>> <> <<public_key::binary-size(33)>> <> _ = decode_base58(pubkey)

    public_key = ECDSA.decode_public_key(public_key, :prime256v1)

    ECDSA.verify?(message, signature, public_key,
      hashfunc: fn msg -> :enacl.generichash(32, msg) end
    )
  end

  @doc """
  Verify that `address` is the public key hash of `pubkey`.

  ## Examples
      iex> pubkey = "sppk7aBerAEA6tv4wzg6FnK7i5YrGtEGFVvNjWhc2QX8bhzpouBVFSW"
      iex> Tezex.Crypto.check_address("tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx", pubkey)
      :ok
      iex> Tezex.Crypto.check_address("tz1burnburnburnburnburnburnburjAYjjX", pubkey)
      {:error, :mismatch}
  """
  @spec check_address(any, any) :: :ok | {:error, :mismatch | :unknown_pubkey_format}
  def check_address(address, pubkey) do
    case derive_address(pubkey) do
      {:ok, ^address} ->
        :ok

      {:ok, _derived} ->
        {:error, :mismatch}

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
  """
  @spec derive_address(binary) :: {:error, :unknown_pubkey_format} | {:ok, binary}
  def derive_address("edpk" <> _ = pubkey) do
    # tz1…
    pkh = <<6, 161, 159>>
    <<13, 15, 37, 217>> <> <<public_key::binary-size(32)>> <> _ = decode_base58(pubkey)

    derive_address(public_key, pkh)
  end

  def derive_address("sppk" <> _ = pubkey) do
    # tz2…
    pkh = <<6, 161, 161>>
    <<3, 254, 226, 86>> <> <<public_key::binary-size(33)>> <> _ = decode_base58(pubkey)

    derive_address(public_key, pkh)
  end

  def derive_address("p2pk" <> _ = pubkey) do
    # tz3…
    pkh = <<6, 161, 164>>
    <<3, 178, 139, 127>> <> <<public_key::binary-size(33)>> <> _ = decode_base58(pubkey)

    derive_address(public_key, pkh)
  end

  def derive_address(_) do
    {:error, :unknown_pubkey_format}
  end

  defp derive_address(pubkey, pkh) do
    derived =
      :enacl.generichash(20, pubkey)
      |> Tezex.Crypto.Base58Check.encode(pkh)

    {:ok, derived}
  end
end
