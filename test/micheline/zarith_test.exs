defmodule Tezex.Micheline.Zarith.Test do
  use ExUnit.Case
  alias Tezex.Micheline
  alias Tezex.Micheline.Zarith
  doctest Micheline.Zarith

  test "encode/decode" do
    n = 1_000_000_000_000
    random = fn -> trunc(:rand.uniform(n) - n / 2) end

    Enum.each(1..5000, fn _ ->
      number = random.()
      assert number == Zarith.decode(Zarith.encode(number))
    end)
  end

  test "decode/1" do
    assert 1_000_000 = Zarith.decode("0080897a")
    assert 917_431_994 = Zarith.decode("00ba9af7ea06")
    assert -917_431_994 = Zarith.decode("00fa9af7ea06")
    assert 365_729 = Zarith.decode("00a1d22c")
    assert -365_729 = Zarith.decode("00e1d22c")
    assert 610_913_435_200 = Zarith.decode("0080f9b9d4c723")
    assert -610_913_435_200 = Zarith.decode("00c0f9b9d4c723")
    assert -33 = Zarith.decode("00610100")
  end

  test "encode/1" do
    assert "80897a" = Zarith.encode(1_000_000)
    assert "a1d22c" = Zarith.encode(365_729)
    assert "e1d22c" = Zarith.encode(-365_729)
    assert "61" = Zarith.encode(-33)
    assert "ba9af7ea06" = Zarith.encode(917_431_994)
    assert "fa9af7ea06" = Zarith.encode(-917_431_994)
    assert "80f9b9d4c723" = Zarith.encode(610_913_435_200)
    assert "c0f9b9d4c723" = Zarith.encode(-610_913_435_200)
  end

  describe "consume/1" do
    test "1_000_000" do
      assert {%{int: 1_000_000}, 8} = Zarith.consume("0080897a")
    end

    test "917_431_994" do
      assert {%{int: 917_431_994}, 12} = Zarith.consume("00ba9af7ea06")
    end

    test "-917_431_994" do
      assert {%{int: -917_431_994}, 12} = Zarith.consume("00fa9af7ea06")
    end

    test "365_729" do
      assert {%{int: 365_729}, 8} = Zarith.consume("00a1d22c")
    end

    test "-365_729" do
      assert {%{int: -365_729}, 8} = Zarith.consume("00e1d22c")
    end

    test "610_913_435_200" do
      assert {%{int: 610_913_435_200}, 14} = Zarith.consume("0080f9b9d4c723")
    end

    test "-610_913_435_200" do
      assert {%{int: -610_913_435_200}, 14} = Zarith.consume("00c0f9b9d4c723")
    end

    test "-33" do
      assert {%{int: -33}, 4} = Zarith.consume("00610100")
      assert {%{int: -33}, 4} = Micheline.hex_to_micheline("00610100")
    end
  end
end
