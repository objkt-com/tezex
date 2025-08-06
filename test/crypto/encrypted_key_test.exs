defmodule Tezex.Crypto.EncryptedKeyTest do
  use ExUnit.Case, async: true

  alias Tezex.Crypto.PrivateKey

  describe "from_encoded_key/2" do
    test "decrypts P256 encrypted key with correct passphrase" do
      encrypted_key =
        "p2esk2TFqgNcoT4u99ut5doGTUFNwo9x4nNvkpM6YMLqXrt4SbFdQnqLM3hoAXLMB2uZYazj6LZGvcoYzk16H6Et"

      passphrase = "test1234"

      assert {:ok, private_key} = PrivateKey.from_encoded_key(encrypted_key, passphrase)
      assert private_key.curve.name == :prime256v1

      # The decrypted secret should be 32 bytes
      assert byte_size(private_key.secret) == 32

      # Expected decrypted key from pytezos reference
      expected_secret = "37a6ff1868a581d09c60377239a95601dc73cd659ecf5d3cee14461c8b8efc9e"
      expected_secret_bytes = Base.decode16!(String.upcase(expected_secret))

      assert private_key.secret == expected_secret_bytes
    end

    test "fails to decrypt P256 encrypted key with wrong passphrase" do
      encrypted_key =
        "p2esk2TFqgNcoT4u99ut5doGTUFNwo9x4nNvkpM6YMLqXrt4SbFdQnqLM3hoAXLMB2uZYazj6LZGvcoYzk16H6Et"

      wrong_passphrase = "wrongpassword"

      assert {:error, :decryption_failed} =
               PrivateKey.from_encoded_key(encrypted_key, wrong_passphrase)
    end

    test "fails to decrypt encrypted key without passphrase" do
      encrypted_key =
        "p2esk2TFqgNcoT4u99ut5doGTUFNwo9x4nNvkpM6YMLqXrt4SbFdQnqLM3hoAXLMB2uZYazj6LZGvcoYzk16H6Et"

      assert {:error, :passphrase_required} = PrivateKey.from_encoded_key(encrypted_key)
    end

    test "decrypts unencrypted P256 key" do
      # This is a test P256 private key (not encrypted)
      unencrypted_key = "p2sk3eRQXajR4mYdScB16aZU3q6Kxo9YvvaXqiPSRsWmxQP3vkmqQn"

      assert {:ok, private_key} = PrivateKey.from_encoded_key(unencrypted_key)
      assert private_key.curve.name == :prime256v1
      assert byte_size(private_key.secret) == 32
    end

    test "handles invalid base58 encoding" do
      # Use a key with correct length but invalid base58 characters
      invalid_key =
        "p2esk2TFqgNcoT4u99ut5doGTUFNwo9x4nNvkpM6YMLqXrt4SbFdQnqLM3hoAXLMB2uZYazj6LZGvcoYzk16H6E0"

      assert {:error, :invalid_base58} = PrivateKey.from_encoded_key(invalid_key, "test1234")
    end

    test "handles unsupported key format" do
      unsupported_key = "xyz123"

      assert {:error, :invalid_curve_prefix} = PrivateKey.from_encoded_key(unsupported_key)
    end

    test "handles public key instead of secret key" do
      public_key = "p2pk65zwHGP9MdvANKkp267F4VzoKqL8DMNpPfTHUNKbm8S9DUqqdpw"

      assert {:error, :not_secret_key} = PrivateKey.from_encoded_key(public_key)
    end

    test "handles wrong key length" do
      # Truncated key
      short_key = "p2esk2TFqgNcoT4u99ut5doGTUFNwo9x4nNvkpM6YMLqXrt4SbFdQnqLM3hoA"

      assert {:error, :invalid_key_length} = PrivateKey.from_encoded_key(short_key, "test1234")
    end
  end

  describe "NaCl decryption" do
    test "correctly decrypts test data matching pytezos" do
      # Test data from pytezos implementation
      encrypted_sk =
        Base.decode16!(
          "970AD820D4790BA150A03D1EB291D3F4958A75A7BA61E66FAC47F7DDFA1E73F32B8021AAF392B62F845D6E6844C26D76"
        )

      salt = Base.decode16!("E52FC24E6528891E")
      passphrase = "test1234"

      expected_plaintext =
        Base.decode16!("37A6FF1868A581D09C60377239A95601DC73CD659ECF5D3CEE14461C8B8EFC9E")

      # Derive encryption key using PBKDF2-HMAC-SHA512
      encryption_key = :crypto.pbkdf2_hmac(:sha512, passphrase, salt, 32768, 32)

      # Decrypt using NaCl secretbox with zero nonce
      # 24 bytes of zeros
      nonce = <<0::192>>

      assert {:ok, decrypted} =
               Tezex.Crypto.NaCl.crypto_secretbox_open(encrypted_sk, nonce, encryption_key)

      assert decrypted == expected_plaintext
    end
  end
end
