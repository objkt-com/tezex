defmodule Tezex.Crypto.PublicKeyTest do
  use ExUnit.Case

  alias Tezex.Crypto.PrivateKey
  alias Tezex.Crypto.PublicKey

  test "string conversion" do
    private_key = PrivateKey.generate()
    public_key_1 = PrivateKey.get_public_key(private_key)
    string = PublicKey.to_string(public_key_1)

    {:ok, public_key_2} = PublicKey.from_string(string)

    assert public_key_1.point.x == public_key_2.point.x
    assert public_key_1.point.y == public_key_2.point.y
    assert public_key_1.curve.name == public_key_2.curve.name
  end
end
