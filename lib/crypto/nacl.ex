defmodule Tezex.Crypto.NaCl do
  @moduledoc """
  NaCl-compatible cryptographic functions for Tezos encrypted key handling.

  This module implements the crypto_secretbox_open functionality needed to decrypt
  Tezos encrypted private keys that use the NaCl/Sodium encryption standard.
  """

  @doc """
  Opens (decrypts) a NaCl secretbox using XSalsa20-Poly1305.

  ## Parameters

  - `ciphertext` - The encrypted data (includes auth tag)
  - `nonce` - 24-byte nonce (usually zeros for Tezos key encryption)
  - `key` - 32-byte encryption key derived from passphrase

  ## Returns

  - `{:ok, plaintext}` - Successfully decrypted data
  - `{:error, reason}` - Decryption failed
  """
  @spec crypto_secretbox_open(binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, :decryption_failed}
  def crypto_secretbox_open(_ciphertext, nonce, _key) when byte_size(nonce) != 24 do
    {:error, :invalid_nonce_length}
  end

  def crypto_secretbox_open(_ciphertext, _nonce, key) when byte_size(key) != 32 do
    {:error, :invalid_key_length}
  end

  def crypto_secretbox_open(ciphertext, nonce, key) do
    try do
      # Use kcl library for proper NaCl secretbox decryption
      case Kcl.secretunbox(ciphertext, nonce, key) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        :error -> {:error, :decryption_failed}
      end
    rescue
      _ -> {:error, :decryption_failed}
    end
  end
end
