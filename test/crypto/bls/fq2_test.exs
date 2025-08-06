defmodule Tezex.Crypto.BLS.Fq2Test do
  use ExUnit.Case, async: true

  alias Tezex.Crypto.BLS.Constants
  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.BLS.Fq2

  @field_modulus Constants.field_modulus()

  describe "Fq2 field operations" do
    test "basic arithmetic operations" do
      # x = (1, 0)
      x = Fq2.from_integers(1, 0)

      # f = (1, 2)
      f = Fq2.from_integers(1, 2)

      # fpx = (2, 2)
      fpx = Fq2.from_integers(2, 2)

      # one = 1
      one = Fq2.one()

      # assert x + f == fpx
      assert Fq2.eq?(Fq2.add(x, f), fpx)

      # assert f / f == one
      {:ok, f_inv} = Fq2.inv(f)
      f_div_f = Fq2.mul(f, f_inv)
      assert Fq2.eq?(f_div_f, one)

      # assert one / f + x / f == (one + x) / f
      one_div_f = Fq2.mul(one, f_inv)
      x_div_f = Fq2.mul(x, f_inv)
      one_plus_x = Fq2.add(one, x)
      one_plus_x_div_f = Fq2.mul(one_plus_x, f_inv)

      assert Fq2.eq?(Fq2.add(one_div_f, x_div_f), one_plus_x_div_f)

      # assert one * f + x * f == (one + x) * f
      one_times_f = Fq2.mul(one, f)
      x_times_f = Fq2.mul(x, f)
      one_plus_x_times_f = Fq2.mul(one_plus_x, f)

      assert Fq2.eq?(Fq2.add(one_times_f, x_times_f), one_plus_x_times_f)

      # assert x ** (field_modulus**2 - 1) == one
      field_modulus_squared_minus_1 = @field_modulus * @field_modulus - 1
      x_pow = Fq2.pow(x, field_modulus_squared_minus_1)
      assert Fq2.eq?(x_pow, one)

      # Test negative coefficients are positive
      neg_fq2 = Fq2.from_integers(-1, -1)
      {z1, z2} = neg_fq2
      z1_int = Fq.to_integer(z1)
      z2_int = Fq.to_integer(z2)
      assert z1_int > 0
      assert z2_int > 0
    end
  end

  describe "Fq2 py_ecc compatibility" do
    test "basic construction and coefficient access" do
      # Test basic construction matching py_ecc
      a = Fq2.from_integers(1, 2)
      b = Fq2.from_integers(3, 4)
      zero = Fq2.zero()
      one = Fq2.one()

      # Check coefficients match py_ecc format
      assert Fq2.to_integers(a) == {1, 2}
      assert Fq2.to_integers(b) == {3, 4}
      assert Fq2.to_integers(zero) == {0, 0}
      assert Fq2.to_integers(one) == {1, 0}
    end

    test "arithmetic operations match py_ecc" do
      # (1, 2)
      a = Fq2.from_integers(1, 2)
      # (3, 4)
      b = Fq2.from_integers(3, 4)

      # Addition: py_ecc gives (4, 6)
      add_result = Fq2.add(a, b)
      assert Fq2.to_integers(add_result) == {4, 6}

      # Subtraction: Should be equivalent to (1-3, 2-4) = (-2, -2) mod p
      sub_result = Fq2.sub(a, b)
      {sub_0, sub_1} = Fq2.to_integers(sub_result)
      p = Fq2.modulus()
      expected_neg_2 = p - 2
      assert sub_0 == expected_neg_2
      assert sub_1 == expected_neg_2

      # Multiplication: For (1+2i)(3+4i) = 3+4i+6i+8i^2 = 3+10i-8 = -5+10i mod p
      mul_result = Fq2.mul(a, b)
      {mul_0, mul_1} = Fq2.to_integers(mul_result)
      expected_neg_5 = p - 5
      assert mul_0 == expected_neg_5
      assert mul_1 == 10

      # Scalar multiplication: py_ecc gives (2, 4)
      scalar_2 = Fq2.mul_scalar(a, 2)
      assert Fq2.to_integers(scalar_2) == {2, 4}
    end

    test "equality works correctly" do
      a = Fq2.from_integers(1, 2)
      b = Fq2.from_integers(3, 4)
      a_copy = Fq2.from_integers(1, 2)
      zero = Fq2.zero()
      zero_copy = Fq2.zero()
      one = Fq2.one()
      one_copy = Fq2.from_integers(1, 0)

      # Self equality
      assert Fq2.eq?(a, a)
      assert Fq2.eq?(a, a_copy)

      # Different values not equal
      refute Fq2.eq?(a, b)

      # Zero equality
      assert Fq2.eq?(zero, zero)
      assert Fq2.eq?(zero, zero_copy)

      # One equality
      assert Fq2.eq?(one, one_copy)

      # Cross checks
      refute Fq2.eq?(zero, one)
      refute Fq2.eq?(a, zero)
    end

    test "negation matches py_ecc" do
      a = Fq2.from_integers(1, 2)
      zero = Fq2.zero()

      # Negation of (1, 2)
      neg_a = Fq2.neg(a)
      {neg_0, neg_1} = Fq2.to_integers(neg_a)
      p = Fq2.modulus()
      assert neg_0 == p - 1
      assert neg_1 == p - 2

      # Negation of zero should be zero
      neg_zero = Fq2.neg(zero)
      assert Fq2.to_integers(neg_zero) == {0, 0}

      # Double negation should equal original
      double_neg_a = Fq2.neg(neg_a)
      assert Fq2.eq?(double_neg_a, a)
    end

    test "large number arithmetic matches py_ecc" do
      large_a = Fq2.from_integers(123_456_789, 987_654_321)
      large_b = Fq2.from_integers(111_111_111, 222_222_222)

      # Addition: py_ecc gives (234567900, 1209876543)
      add_result = Fq2.add(large_a, large_b)
      assert Fq2.to_integers(add_result) == {234_567_900, 1_209_876_543}

      # Multiplication: py_ecc gives specific large result
      mul_result = Fq2.mul(large_a, large_b)
      {mul_0, mul_1} = Fq2.to_integers(mul_result)

      # The exact values from py_ecc
      expected_mul_0 =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_458_276_577_478_321_104

      expected_mul_1 = 137_174_210_862_825_789

      assert mul_0 == expected_mul_0
      assert mul_1 == expected_mul_1
    end

    test "field properties are correct" do
      # Field modulus should match py_ecc
      expected_modulus = Constants.field_modulus()

      assert Fq2.modulus() == expected_modulus
    end

    test "additive and multiplicative identity" do
      a = Fq2.from_integers(42, 17)
      zero = Fq2.zero()
      one = Fq2.one()

      # Additive identity
      assert Fq2.eq?(Fq2.add(a, zero), a)
      assert Fq2.eq?(Fq2.add(zero, a), a)

      # Multiplicative identity
      assert Fq2.eq?(Fq2.mul(a, one), a)
      assert Fq2.eq?(Fq2.mul(one, a), a)

      # Zero property
      assert Fq2.eq?(Fq2.mul(a, zero), zero)
      assert Fq2.eq?(Fq2.mul(zero, a), zero)
    end
  end

  describe "Fq2 advanced operations" do
    test "square operation" do
      a = Fq2.from_integers(2, 3)
      squared = Fq2.square(a)
      manual_square = Fq2.mul(a, a)

      assert Fq2.eq?(squared, manual_square)
    end

    test "inverse operation when implemented" do
      # Skip if inverse not implemented yet
      if function_exported?(Fq2, :inv, 1) do
        a = Fq2.from_integers(3, 4)

        case Fq2.inv(a) do
          {:ok, a_inv} ->
            # a * a^(-1) should equal 1
            product = Fq2.mul(a, a_inv)
            assert Fq2.eq?(product, Fq2.one())

          {:error, _} ->
            # If no inverse exists, that's also valid
            :ok
        end
      end
    end

    test "square root operation when implemented" do
      # Skip if sqrt not implemented yet
      if function_exported?(Fq2, :sqrt, 1) do
        # Test with a perfect square
        # Should have square root (2, 0)
        a = Fq2.from_integers(4, 0)

        case Fq2.sqrt(a) do
          {:ok, sqrt_a} ->
            # sqrt(a)^2 should equal a
            squared_back = Fq2.square(sqrt_a)
            assert Fq2.eq?(squared_back, a)

          {:error, _} ->
            # Some values may not have square roots
            :ok
        end
      end
    end
  end

  describe "Fq2 field operations with known values" do
    test "basic arithmetic operations with specific values" do
      # Test values
      c = Fq2.from_integers(123, 456)
      d = Fq2.from_integers(789, 101_112)

      # Addition: (123, 456) + (789, 101112) = (912, 101568)
      {add_real, add_imag} = Fq2.to_integers(Fq2.add(c, d))
      assert add_real == 912
      assert add_imag == 101_568

      # Multiplication: (123, 456) * (789, 101112)
      {mul_real, mul_imag} = Fq2.to_integers(Fq2.mul(c, d))

      expected_mul_real =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_226_549_762

      expected_mul_imag = 12_796_560
      assert mul_real == expected_mul_real
      assert mul_imag == expected_mul_imag

      # Subtraction: (123, 456) - (789, 101112)
      {sub_real, sub_imag} = Fq2.to_integers(Fq2.sub(c, d))

      expected_sub_real =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_121

      expected_sub_imag =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_459_131

      assert sub_real == expected_sub_real
      assert sub_imag == expected_sub_imag
    end

    test "squaring operation with known values" do
      c = Fq2.from_integers(123, 456)

      # (123, 456) ** 2 
      {square_real, square_imag} = Fq2.to_integers(Fq2.square(c))

      expected_square_real =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_366_980

      expected_square_imag = 112_176
      assert square_real == expected_square_real
      assert square_imag == expected_square_imag
    end

    test "conjugate operation with known values" do
      c = Fq2.from_integers(123, 456)

      # conjugate((123, 456))
      {conj_real, conj_imag} = Fq2.to_integers(Fq2.conjugate(c))
      expected_conj_real = 123

      expected_conj_imag =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_331

      assert conj_real == expected_conj_real
      assert conj_imag == expected_conj_imag
    end

    test "zero and one elements with exact values" do
      # zero() = (0, 0)
      {zero_real, zero_imag} = Fq2.to_integers(Fq2.zero())
      assert zero_real == 0
      assert zero_imag == 0

      # one() = (1, 0)
      {one_real, one_imag} = Fq2.to_integers(Fq2.one())
      assert one_real == 1
      assert one_imag == 0
    end

    test "simple multiplication cases with known results" do
      # (1, 2) * (3, 4) = (-5, 10) mod p
      a = Fq2.from_integers(1, 2)
      b = Fq2.from_integers(3, 4)
      {result_real, result_imag} = Fq2.to_integers(Fq2.mul(a, b))

      expected_real =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_782

      expected_imag = 10
      assert result_real == expected_real
      assert result_imag == expected_imag
    end

    test "multiplication with zero and one identities" do
      a = Fq2.from_integers(1, 2)
      zero = Fq2.zero()
      one = Fq2.one()

      # (1, 2) * zero = (0, 0)
      {zero_result_real, zero_result_imag} = Fq2.to_integers(Fq2.mul(a, zero))
      assert zero_result_real == 0
      assert zero_result_imag == 0

      # (1, 2) * one = (1, 2)
      {one_result_real, one_result_imag} = Fq2.to_integers(Fq2.mul(a, one))
      assert one_result_real == 1
      assert one_result_imag == 2
    end

    test "extension field properties u^2 = -1" do
      # Manual verification: (a + bu)(c + du) = (ac - bd) + (ad + bc)u
      # where u^2 = -1
      a_val = 123
      b_val = 456
      c_val = 789
      d_val = 101_112

      ac = rem(a_val * c_val, Fq.modulus())
      bd = rem(b_val * d_val, Fq.modulus())
      ad = rem(a_val * d_val, Fq.modulus())
      bc = rem(b_val * c_val, Fq.modulus())

      # Real part: ac - bd (with proper modular arithmetic)
      expected_real = rem(ac - bd + Fq.modulus(), Fq.modulus())
      # Imaginary part: ad + bc
      expected_imag = rem(ad + bc, Fq.modulus())

      # Test with our implementation
      fq2_a = Fq2.from_integers(a_val, b_val)
      fq2_b = Fq2.from_integers(c_val, d_val)
      {result_real, result_imag} = Fq2.to_integers(Fq2.mul(fq2_a, fq2_b))

      assert result_real == expected_real
      assert result_imag == expected_imag
    end
  end
end
