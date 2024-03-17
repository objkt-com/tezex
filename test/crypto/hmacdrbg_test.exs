defmodule Tezex.Crypto.HMACDRBG.Test do
  alias Tezex.Crypto.HMACDRBG
  use ExUnit.Case

  test "test sha256 1" do
    entropy = "totally random0123456789"
    nonce = "secret nonce"
    pers = "my drbg"
    drbg = HMACDRBG.init(entropy, nonce, pers)

    {result, _} = HMACDRBG.generate(drbg, 32)

    assert :binary.encode_hex(result, :lowercase) ==
             "018ec5f8e08c41e5ac974eb129ac297c5388ee1864324fa13d9b15cf98d9a157"
  end

  test "test sha256 2" do
    entropy = "totally random0123456789"
    nonce = "secret nonce"
    drbg = HMACDRBG.init(entropy, nonce)

    {result, _} = HMACDRBG.generate(drbg, 32)

    assert :binary.encode_hex(result, :lowercase) ==
             "ed5d61ecf0ef38258e62f03bbb49f19f2cd07ba5145a840d83b134d5963b3633"
  end

  test "test reseeding" do
    entropy = "totally random string with many chars that I typed in agony"
    nonce = "nonce"
    pers = "pers"

    drbg_original = HMACDRBG.init(entropy, nonce, pers)
    drbg_reseed = HMACDRBG.init(entropy, nonce, pers)

    {result_original, _} = HMACDRBG.generate(drbg_original, 32)
    {result_reseeded, drbg_reseed} = HMACDRBG.generate(drbg_reseed, 32)

    assert result_original == result_reseeded

    drbg_reseed = HMACDRBG.reseed(drbg_reseed, "another absolutely random string")

    {result_original, _} = HMACDRBG.generate(drbg_original, 32)
    {result_reseeded, _} = HMACDRBG.generate(drbg_reseed, 32)
    assert result_original != result_reseeded
  end

  describe "NIST" do
    @fixtures Jason.decode!(File.read!("./test/fixtures/hmac-drbg-nist.json"))

    # fixtures = [List.first(@fixtures)]

    for t <- @fixtures do
      test "vector #{t["name"]}" do
        entropy = :binary.decode_hex(unquote(t["entropy"]))
        nonce = :binary.decode_hex(unquote(t["nonce"]))
        pers = unquote(t["pers"])
        pers = if is_nil(pers), do: pers, else: :binary.decode_hex(pers)
        add = unquote(t["add"])
        expected = unquote(t["expected"])

        drbg = HMACDRBG.init(entropy, nonce, pers)

        {result, _} =
          Enum.reduce(add, {nil, drbg}, fn add, {_result, drbg} ->
            HMACDRBG.generate(drbg, 256, add)
          end)

        assert :binary.encode_hex(result, :lowercase) == expected
      end
    end
  end
end
