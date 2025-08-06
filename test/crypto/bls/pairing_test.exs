defmodule Tezex.Crypto.BLS.PairingTest do
  use ExUnit.Case, async: true

  alias Tezex.Crypto.BLS.Constants
  alias Tezex.Crypto.BLS.Fq12
  alias Tezex.Crypto.BLS.Fr
  alias Tezex.Crypto.BLS.G1
  alias Tezex.Crypto.BLS.G2
  alias Tezex.Crypto.BLS.Pairing

  @curve_order Constants.curve_order()

  describe "Pairing operations" do
    test "pairing with negative G1" do
      g1 = G1.generator()
      g2 = G2.generator()

      # p1 = pairing(G1, G2)
      p1 = Pairing.pairing(g1, g2)

      # pn1 = pairing(neg(G1), G2)
      neg_g1 = G1.negate(g1)
      pn1 = Pairing.pairing(neg_g1, g2)

      # assert p1 * pn1 == 1
      product = Fq12.mul(p1, pn1)
      assert Fq12.is_one?(product)
    end

    test "pairing output order" do
      g1 = G1.generator()
      g2 = G2.generator()

      # p1 = pairing(G1, G2)
      p1 = Pairing.pairing(g1, g2)

      # assert p1**curve_order == 1
      p1_pow_order = Fq12.pow(p1, @curve_order)
      assert Fq12.is_one?(p1_pow_order)
    end

    test "pairing bilinearity on G1" do
      g1 = G1.generator()
      g2 = G2.generator()
      two = Fr.from_integer(2)

      # p1 = pairing(G1, G2)
      p1 = Pairing.pairing(g1, g2)

      # p2 = pairing(multiply(G1, 2), G2)
      g1_times_2 = G1.mul(g1, two)
      p2 = Pairing.pairing(g1_times_2, g2)

      # assert p1 * p1 == p2
      p1_squared = Fq12.mul(p1, p1)
      assert Fq12.eq?(p1_squared, p2)
    end

    test "pairing is non-degenerate" do
      g1 = G1.generator()
      g2 = G2.generator()
      two = Fr.from_integer(2)

      # p1 = pairing(G1, G2)
      p1 = Pairing.pairing(g1, g2)

      # p2 = pairing(multiply(G1, 2), G2)
      g1_times_2 = G1.mul(g1, two)
      p2 = Pairing.pairing(g1_times_2, g2)

      # np1 = pairing(G1, neg(G2))
      neg_g2 = G2.negate(g2)
      np1 = Pairing.pairing(g1, neg_g2)

      # assert p1 != p2 and p1 != np1 and p2 != np1
      refute Fq12.eq?(p1, p2)
      refute Fq12.eq?(p1, np1)
      refute Fq12.eq?(p2, np1)
    end

    test "pairing bilinearity on G2" do
      g1 = G1.generator()
      g2 = G2.generator()
      two = Fr.from_integer(2)

      # p1 = pairing(G1, G2)
      p1 = Pairing.pairing(g1, g2)

      # po2 = pairing(G1, multiply(G2, 2))
      g2_times_2 = G2.mul(g2, two)
      po2 = Pairing.pairing(g1, g2_times_2)

      # assert p1 * p1 == po2
      p1_squared = Fq12.mul(p1, p1)
      assert Fq12.eq?(p1_squared, po2)
    end

    test "pairing composite check" do
      g1 = G1.generator()
      g2 = G2.generator()
      twenty_seven = Fr.from_integer(27)
      thirty_seven = Fr.from_integer(37)
      nine_ninety_nine = Fr.from_integer(999)

      # p3 = pairing(multiply(G1, 37), multiply(G2, 27))
      g2_times_27 = G2.mul(g2, twenty_seven)
      g1_times_37 = G1.mul(g1, thirty_seven)
      p3 = Pairing.pairing(g1_times_37, g2_times_27)

      # po3 = pairing(multiply(G1, 999), G2)
      g1_times_999 = G1.mul(g1, nine_ninety_nine)
      po3 = Pairing.pairing(g1_times_999, g2)

      # assert p3 == po3
      assert Fq12.eq?(p3, po3)
    end
  end
end
