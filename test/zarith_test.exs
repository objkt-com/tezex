defmodule Tezex.ZarithTest do
  use ExUnit.Case, async: true

  alias Tezex.Zarith
  doctest Zarith, import: true

  test "encode/decode" do
    n = 1_000_000_000_000
    h = n / 2
    random = fn -> trunc(:rand.uniform(n) - h) end

    Enum.each(1..5000, fn _ ->
      number = random.()
      assert number == Zarith.decode(Zarith.encode(number))
    end)
  end

  test "decode/1" do
    assert 1_000_000 = Zarith.decode("80897a")
    assert 917_431_994 = Zarith.decode("ba9af7ea06")
    assert -917_431_994 = Zarith.decode("fa9af7ea06")
    assert 365_729 = Zarith.decode("a1d22c")
    assert -365_729 = Zarith.decode("e1d22c")
    assert 610_913_435_200 = Zarith.decode("80f9b9d4c723")
    assert -610_913_435_200 = Zarith.decode("c0f9b9d4c723")
    assert -33 = Zarith.decode("610100")
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
      packed = "80897a"
      assert {%{int: "1000000"}, byte_size(packed)} == Zarith.consume(packed)
    end

    test "917_431_994" do
      packed = "ba9af7ea06"
      assert {%{int: "917431994"}, byte_size(packed)} == Zarith.consume(packed)
    end

    test "-917_431_994" do
      packed = "fa9af7ea06"
      assert {%{int: "-917431994"}, byte_size(packed)} == Zarith.consume(packed)
    end

    test "365_729" do
      packed = "a1d22c"
      assert {%{int: "365729"}, byte_size(packed)} == Zarith.consume(packed)
    end

    test "-365_729" do
      packed = "e1d22c"
      assert {%{int: "-365729"}, byte_size(packed)} == Zarith.consume(packed)
    end

    test "610_913_435_200" do
      packed = "80f9b9d4c723"
      assert {%{int: "610913435200"}, byte_size(packed)} == Zarith.consume(packed)
    end

    test "-610_913_435_200" do
      packed = "c0f9b9d4c723"
      assert {%{int: "-610913435200"}, byte_size(packed)} == Zarith.consume(packed)
    end
  end

  describe "malformed input" do
    test "raises on truncated input with continuation bit set" do
      # 0x80: continuation=1, sign=0, tail=0, claims more bytes follow but none do
      assert_raise ArgumentError, fn -> Zarith.decode("80") end
      # 0xff: continuation=1, sign=1, tail=63, same truncation
      assert_raise ArgumentError, fn -> Zarith.decode("ff") end
      # Multi-byte truncation: first byte continues, second byte continues, then ends
      assert_raise ArgumentError, fn -> Zarith.decode("8080") end
    end

    test "raises on empty input" do
      assert_raise ArgumentError, fn -> Zarith.consume("") end
      assert_raise ArgumentError, fn -> Zarith.decode("") end
    end

    test "raises on odd-length hex input" do
      assert_raise ArgumentError, fn -> Zarith.consume("a1d22") end
      assert_raise ArgumentError, fn -> Zarith.decode("a1d22") end
    end
  end
end
