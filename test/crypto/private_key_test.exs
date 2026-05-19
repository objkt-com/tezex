defmodule Tezex.Crypto.PrivateKeyTest do
  use ExUnit.Case, async: true

  alias Tezex.Crypto.PrivateKey

  test "string conversion" do
    private_key1 = PrivateKey.generate()

    string = PrivateKey.to_string(private_key1)

    {:ok, private_key2} = PrivateKey.from_string(string)

    assert private_key1.secret == private_key2.secret
    assert private_key1.curve == private_key2.curve
  end

  describe "from_encoded_key/2 error reporting" do
    test "returns :invalid_checksum for keys with corrupted checksum, not :invalid_base58" do
      pk = PrivateKey.generate(nil, :secp256k1)
      valid_spsk = Tezex.Crypto.Base58Check.encode(pk.secret, <<17, 162, 224, 201>>)

      assert {:ok, _} = PrivateKey.from_encoded_key(valid_spsk)

      # Flip a base58 char in the checksum suffix to corrupt the checksum
      # without breaking base58 decodability.
      last = String.last(valid_spsk)
      replacement = if last == "1", do: "2", else: "1"
      corrupted = String.slice(valid_spsk, 0..-2//1) <> replacement

      assert {:error, :invalid_checksum} = PrivateKey.from_encoded_key(corrupted)
    end
  end
end
