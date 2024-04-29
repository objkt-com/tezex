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
end
