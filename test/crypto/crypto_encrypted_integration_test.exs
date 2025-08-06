defmodule Tezex.Crypto.EncryptedIntegrationTest do
  use ExUnit.Case, async: true

  alias Tezex.Crypto

  describe "encrypted key integration with main Crypto module" do
    test "signs messages with encrypted P256 key" do
      encrypted_key =
        "p2esk2TFqgNcoT4u99ut5doGTUFNwo9x4nNvkpM6YMLqXrt4SbFdQnqLM3hoAXLMB2uZYazj6LZGvcoYzk16H6Et"

      passphrase = "test1234"

      # Test signing a message with the encrypted key
      message = "hello world"

      signature = Crypto.sign_message({encrypted_key, passphrase}, message)

      # The signature should be valid and in P256 format
      assert String.starts_with?(signature, "p2sig")
      # P256 signature length in base58
      assert String.length(signature) == 98
    end

    test "signs operations with encrypted P256 key" do
      encrypted_key =
        "p2esk2TFqgNcoT4u99ut5doGTUFNwo9x4nNvkpM6YMLqXrt4SbFdQnqLM3hoAXLMB2uZYazj6LZGvcoYzk16H6Et"

      passphrase = "test1234"

      # Test signing an operation with the encrypted key
      operation_bytes = "030000000000000000000000000000000000000000000000000000000000000000"

      signature = Crypto.sign_operation({encrypted_key, passphrase}, operation_bytes)

      # The signature should be valid and in P256 format
      assert String.starts_with?(signature, "p2sig")
      # P256 signature length in base58
      assert String.length(signature) == 98
    end

    test "fails to sign without passphrase for encrypted key" do
      encrypted_key =
        "p2esk2TFqgNcoT4u99ut5doGTUFNwo9x4nNvkpM6YMLqXrt4SbFdQnqLM3hoAXLMB2uZYazj6LZGvcoYzk16H6Et"

      # Should throw an error when trying to use encrypted key without passphrase
      assert catch_throw(Crypto.sign_message(encrypted_key, "hello world")) ==
               "missing passphrase"
    end

    test "works with unencrypted P256 key for backward compatibility" do
      unencrypted_key = "p2sk3eRQXajR4mYdScB16aZU3q6Kxo9YvvaXqiPSRsWmxQP3vkmqQn"

      # Test signing with unencrypted key (should still work)
      message = "hello world"
      signature = Crypto.sign_message(unencrypted_key, message)

      # The signature should be valid and in P256 format
      assert String.starts_with?(signature, "p2sig")
      assert String.length(signature) == 98
    end
  end
end
