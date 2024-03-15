defmodule Tezex.Crypto.HMACDRBG.Test do
  alias Tezex.Crypto.HMACDRBG
  use ExUnit.Case

  test "test sha256 1" do
    entropy = "totally random0123456789"
    nonce = "secret nonce"
    pers = "my drbg"
    drbg = HMACDRBG.new(entropy, nonce, pers)

    {result, _} = HMACDRBG.generate(drbg)

    assert :binary.encode_hex(result, :lowercase) ==
             "018ec5f8e08c41e5ac974eb129ac297c5388ee1864324fa13d9b15cf98d9a157"
  end

  test "test sha256 2" do
    entropy = "totally random0123456789"
    nonce = "secret nonce"
    drbg = HMACDRBG.new(entropy, nonce)

    {result, _} = HMACDRBG.generate(drbg)

    assert :binary.encode_hex(result, :lowercase) ==
             "ed5d61ecf0ef38258e62f03bbb49f19f2cd07ba5145a840d83b134d5963b3633"
  end

  test "test reseeding" do
    entropy = "totally random string with many chars that I typed in agony"
    nonce = "nonce"
    pers = "pers"

    drbg_original = HMACDRBG.new(entropy, nonce, pers)
    drbg_reseed = HMACDRBG.new(entropy, nonce, pers)

    {result_original, _} = HMACDRBG.generate(drbg_original)
    {result_reseeded, drbg_reseed} = HMACDRBG.generate(drbg_reseed)

    assert result_original == result_reseeded

    drbg_reseed = HMACDRBG.reseed(drbg_reseed, "another absolutely random string")

    {result_original, _} = HMACDRBG.generate(drbg_original)
    {result_reseeded, _} = HMACDRBG.generate(drbg_reseed)
    assert result_original != result_reseeded
  end
end
