defmodule Tezex.Crypto.BLS.Fq12Test do
  use ExUnit.Case, async: true

  alias Tezex.Crypto.BLS.Constants
  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.BLS.Fq12
  alias Tezex.Crypto.BLS.Fq2

  describe "Fq Properties" do
    test "pow one on random element equals the same element" do
      for _ <- 1..100 do
        e = Fq.random()
        assert Fq.eq?(Fq.pow(e, 1), e)
      end
    end

    test "pow element to small powers works correctly" do
      # Test basic exponentiation properties instead of complex field theory
      for _ <- 1..20 do
        x = Fq.random()

        # Test x^2 = x * x
        x_squared_pow = Fq.pow(x, 2)
        x_squared_mul = Fq.mul(x, x)
        assert Fq.eq?(x_squared_pow, x_squared_mul)

        # Test x^3 = x * x * x
        x_cubed_pow = Fq.pow(x, 3)
        x_cubed_mul = Fq.mul(Fq.mul(x, x), x)
        assert Fq.eq?(x_cubed_pow, x_cubed_mul)
      end
    end

    test "pow element to larger powers works" do
      # Test that exponentiation is consistent
      for _ <- 1..10 do
        x = Fq.random()

        unless Fq.is_zero?(x) do
          # Test that x^a * x^b = x^(a+b)
          a = :rand.uniform(20)
          b = :rand.uniform(20)

          x_pow_a = Fq.pow(x, a)
          x_pow_b = Fq.pow(x, b)
          product = Fq.mul(x_pow_a, x_pow_b)

          x_pow_sum = Fq.pow(x, a + b)
          assert Fq.eq?(product, x_pow_sum)
        end
      end
    end

    test "pow with exponent zero equals one" do
      for _ <- 1..50 do
        x = Fq.random()
        result = Fq.pow(x, 0)
        assert Fq.eq?(result, Fq.one())
      end
    end

    test "pow inverse relationship" do
      # Test x * x^(-1) = 1 using pow and inv
      for _ <- 1..20 do
        x = Fq.random()

        unless Fq.is_zero?(x) do
          case Fq.inv(x) do
            {:ok, x_inv} ->
              # Test that x^1 * x^(-1) = 1
              x_pow_1 = Fq.pow(x, 1)
              product = Fq.mul(x_pow_1, x_inv)
              assert Fq.eq?(product, Fq.one())

            {:error, _} ->
              # Skip if inverse doesn't exist
              :ok
          end
        end
      end
    end
  end

  describe "Fq2 Properties" do
    test "pow one on random Fq2 element equals the same element" do
      for _ <- 1..100 do
        e = random_fq2()
        assert Fq2.eq?(Fq2.pow(e, 1), e)
      end
    end

    test "Fq2 multiplicative properties" do
      for _ <- 1..50 do
        a = random_fq2()
        b = random_fq2()

        unless Fq2.is_zero?(a) or Fq2.is_zero?(b) do
          # Test that (a * b) * inv(b) = a (when possible)
          product = Fq2.mul(a, b)

          case Fq2.inv(b) do
            {:ok, b_inv} ->
              result = Fq2.mul(product, b_inv)
              assert Fq2.eq?(result, a)

            {:error, _} ->
              # Skip if b is not invertible
              :ok
          end
        end
      end
    end

    test "Fq2 additive properties" do
      for _ <- 1..100 do
        a = random_fq2()
        b = random_fq2()

        # Test commutativity: a + b = b + a
        sum1 = Fq2.add(a, b)
        sum2 = Fq2.add(b, a)
        assert Fq2.eq?(sum1, sum2)

        # Test identity: a + 0 = a
        sum_zero = Fq2.add(a, Fq2.zero())
        assert Fq2.eq?(sum_zero, a)

        # Test inverse: a + (-a) = 0
        neg_a = Fq2.neg(a)
        sum_neg = Fq2.add(a, neg_a)
        assert Fq2.eq?(sum_neg, Fq2.zero())
      end
    end

    test "Fq2 norm and conjugate properties" do
      for _ <- 1..50 do
        a = random_fq2()

        # Test that norm(a) = a * conj(a)
        norm_a = Fq2.norm(a)
        conj_a = Fq2.conjugate(a)
        product = Fq2.mul(a, conj_a)

        # norm returns Fq element, product is Fq2, so we compare the real part
        {real_part, imag_part} = product
        assert Fq.eq?(norm_a, real_part)
        assert Fq2.is_zero?({Fq.zero(), imag_part}) or Fq.is_zero?(imag_part)

        # Test conjugate of conjugate: conj(conj(a)) = a
        conj_conj_a = Fq2.conjugate(conj_a)
        assert Fq2.eq?(conj_conj_a, a)
      end
    end
  end

  describe "is_one tests" do
    test "is_one with random Fq value" do
      for _ <- 1..100 do
        random_fq = Fq.random()
        # Random values should almost never be one
        refute Fq.is_one?(random_fq)
      end
    end

    test "is_one with zero" do
      refute Fq.is_one?(Fq.zero())
      refute Fq2.is_one?(Fq2.zero())
    end

    test "is_one with actual one" do
      assert Fq.is_one?(Fq.one())
      assert Fq2.is_one?(Fq2.one())
    end

    test "Fq2 is_one with random value" do
      for _ <- 1..100 do
        random_fq2 = random_fq2()
        # Random Fq2 values should almost never be one
        refute Fq2.is_one?(random_fq2)
      end
    end
  end

  describe "is_zero tests" do
    test "is_zero with random Fq value" do
      for _ <- 1..100 do
        random_fq = Fq.random()
        # Random values should almost never be zero
        refute Fq.is_zero?(random_fq)
      end
    end

    test "is_zero with actual zero" do
      assert Fq.is_zero?(Fq.zero())
      assert Fq2.is_zero?(Fq2.zero())
    end

    test "is_zero with one" do
      refute Fq.is_zero?(Fq.one())
      refute Fq2.is_zero?(Fq2.one())
    end

    test "Fq2 is_zero with random value" do
      for _ <- 1..100 do
        random_fq2 = random_fq2()
        # Random Fq2 values should almost never be zero
        refute Fq2.is_zero?(random_fq2)
      end
    end
  end

  describe "Fq field operations" do
    test "field axioms - additive group" do
      a = Fq.random()
      b = Fq.random()
      c = Fq.random()

      # Associativity: (a + b) + c = a + (b + c)
      left = Fq.add(Fq.add(a, b), c)
      right = Fq.add(a, Fq.add(b, c))
      assert Fq.eq?(left, right)

      # Commutativity: a + b = b + a
      sum1 = Fq.add(a, b)
      sum2 = Fq.add(b, a)
      assert Fq.eq?(sum1, sum2)

      # Identity: a + 0 = a
      assert Fq.eq?(Fq.add(a, Fq.zero()), a)

      # Inverse: a + (-a) = 0
      assert Fq.eq?(Fq.add(a, Fq.neg(a)), Fq.zero())
    end

    test "field axioms - multiplicative group" do
      a = Fq.random()
      b = Fq.random()
      c = Fq.random()

      # Associativity: (a * b) * c = a * (b * c)
      left = Fq.mul(Fq.mul(a, b), c)
      right = Fq.mul(a, Fq.mul(b, c))
      assert Fq.eq?(left, right)

      # Commutativity: a * b = b * a
      prod1 = Fq.mul(a, b)
      prod2 = Fq.mul(b, a)
      assert Fq.eq?(prod1, prod2)

      # Identity: a * 1 = a
      assert Fq.eq?(Fq.mul(a, Fq.one()), a)

      # Distributivity: a * (b + c) = a * b + a * c
      sum_bc = Fq.add(b, c)
      left_dist = Fq.mul(a, sum_bc)
      right_dist = Fq.add(Fq.mul(a, b), Fq.mul(a, c))
      assert Fq.eq?(left_dist, right_dist)
    end

    test "modular inverse properties" do
      for _ <- 1..50 do
        a = Fq.random()

        unless Fq.is_zero?(a) do
          case Fq.inv(a) do
            {:ok, a_inv} ->
              # a * a^(-1) = 1
              product = Fq.mul(a, a_inv)
              assert Fq.eq?(product, Fq.one())

              # (a^(-1))^(-1) = a
              case Fq.inv(a_inv) do
                {:ok, a_inv_inv} ->
                  assert Fq.eq?(a_inv_inv, a)

                {:error, _} ->
                  flunk("Double inverse should exist")
              end

            {:error, _} ->
              flunk("Non-zero element should have inverse")
          end
        end
      end
    end

    test "square root properties when they exist" do
      for _ <- 1..20 do
        a = Fq.random()

        case Fq.sqrt(a) do
          {:ok, sqrt_a} ->
            # sqrt(a)^2 = a
            square = Fq.square(sqrt_a)
            assert Fq.eq?(square, a)

          {:error, :no_sqrt} ->
            # Not all elements have square roots
            :ok
        end
      end
    end
  end

  describe "Fq2 extension field operations" do
    test "Fq2 quadratic extension properties" do
      # Test that u^2 = -1 in Fq2 construction
      # Since Fq2 = Fq[u]/(u^2 + 1), we have u^2 + 1 = 0, so u^2 = -1

      # u is represented as (0, 1) in Fq2
      u = Fq2.new(Fq.zero(), Fq.one())
      u_squared = Fq2.square(u)
      minus_one = Fq2.new(Fq.neg(Fq.one()), Fq.zero())

      assert Fq2.eq?(u_squared, minus_one)
    end

    test "Fq2 multiplication formula" do
      # (a + bu)(c + du) = (ac - bd) + (ad + bc)u
      for _ <- 1..20 do
        a = Fq.random()
        b = Fq.random()
        c = Fq.random()
        d = Fq.random()

        fq2_1 = Fq2.new(a, b)
        fq2_2 = Fq2.new(c, d)

        product = Fq2.mul(fq2_1, fq2_2)

        # Calculate expected result manually
        ac = Fq.mul(a, c)
        bd = Fq.mul(b, d)
        ad = Fq.mul(a, d)
        bc = Fq.mul(b, c)

        expected_real = Fq.sub(ac, bd)
        expected_imag = Fq.add(ad, bc)
        expected = Fq2.new(expected_real, expected_imag)

        assert Fq2.eq?(product, expected)
      end
    end

    test "Fq2 from_integers helper" do
      a_int = 12345
      b_int = 67890

      fq2_elem = Fq2.from_integers(a_int, b_int)
      {real_part, imag_part} = fq2_elem

      assert Fq.eq?(real_part, Fq.from_integer(a_int))
      assert Fq.eq?(imag_part, Fq.from_integer(b_int))
    end
  end

  describe "Fq py_ecc compatibility" do
    test "basic arithmetic matches py_ecc" do
      # py_ecc: FQ(5) + FQ(3) = 8
      a = Fq.from_integer(5)
      b = Fq.from_integer(3)
      result = Fq.add(a, b)
      assert Fq.to_integer(result) == 8

      # py_ecc: FQ(5) * FQ(3) = 15
      result = Fq.mul(a, b)
      assert Fq.to_integer(result) == 15

      # py_ecc: FQ(5) - FQ(3) = 2
      result = Fq.sub(a, b)
      assert Fq.to_integer(result) == 2

      # py_ecc: FQ(15) / FQ(3) = 5
      a15 = Fq.from_integer(15)
      {:ok, result} = Fq.inv(b)
      result = Fq.mul(a15, result)
      assert Fq.to_integer(result) == 5
    end

    test "inverse operations match py_ecc" do
      # py_ecc: FQ(3) inverse = specific value
      b = Fq.from_integer(3)
      {:ok, inv_b} = Fq.inv(b)

      expected_inv =
        2_668_273_036_814_444_928_945_193_217_157_269_437_704_588_546_626_005_256_888_038_757_416_021_100_327_225_242_961_791_752_752_677_109_358_596_181_706_525

      assert Fq.to_integer(inv_b) == expected_inv

      # py_ecc: FQ(3) * inv(FQ(3)) = 1
      result = Fq.mul(b, inv_b)
      assert Fq.to_integer(result) == 1
    end
  end

  describe "Fq2 py_ecc compatibility" do
    test "basic arithmetic matches py_ecc" do
      # py_ecc: FQ2([1, 2]) + FQ2([3, 4]) = (4, 6)
      a = Fq2.from_integers(1, 2)
      b = Fq2.from_integers(3, 4)
      result = Fq2.add(a, b)
      {real, imag} = Fq2.to_integers(result)
      assert {real, imag} == {4, 6}

      # py_ecc: FQ2([1, 2]) - FQ2([3, 4]) = (p-2, p-2) where p is field modulus
      result = Fq2.sub(a, b)
      {real, imag} = Fq2.to_integers(result)
      p = Fq.modulus()
      expected_val = p - 2
      assert {real, imag} == {expected_val, expected_val}
    end

    test "multiplication matches py_ecc" do
      # py_ecc: FQ2([1, 2]) * FQ2([3, 4]) 
      # = (1*3 - 2*4) + (1*4 + 2*3)*u 
      # = (3 - 8) + (4 + 6)*u
      # = -5 + 10*u
      # = (p-5, 10) where p is field modulus
      a = Fq2.from_integers(1, 2)
      b = Fq2.from_integers(3, 4)
      result = Fq2.mul(a, b)
      {real, imag} = Fq2.to_integers(result)

      p = Fq.modulus()
      # -5 mod p
      expected_real = p - 5
      expected_imag = 10

      assert {real, imag} == {expected_real, expected_imag}
    end

    test "division and inverse match py_ecc" do
      # py_ecc: FQ2([1, 2]) / FQ2([1, 2]) = (1, 0)
      a = Fq2.from_integers(1, 2)
      {:ok, inv_a} = Fq2.inv(a)
      result = Fq2.mul(a, inv_a)
      {real, imag} = Fq2.to_integers(result)
      assert {real, imag} == {1, 0}

      # py_ecc: FQ2([1, 2]) / FQ2([3, 4]) gives specific values
      b = Fq2.from_integers(3, 4)
      {:ok, inv_b} = Fq2.inv(b)
      result = Fq2.mul(a, inv_b)

      # Verify by multiplying back
      verify = Fq2.mul(result, b)
      {verify_real, verify_imag} = Fq2.to_integers(verify)
      assert {verify_real, verify_imag} == {1, 2}
    end
  end

  describe "Fq12 py_ecc compatibility" do
    alias Tezex.Crypto.BLS.Fq12

    # BLS12-381 FQ12 modulus coefficients from py_ecc
    @fq12_modulus_coeffs [2, 0, 0, 0, 0, 0, -2, 0, 0, 0, 0, 0]

    test "5 * (1/5) should equal 1" do
      # Create element representing 5
      five = Fq12.new([Fq.from_integer(5) | List.duplicate(Fq.zero(), 11)], @fq12_modulus_coeffs)

      # Compute inverse
      five_inv = Fq12.inv(five)

      # Multiply should give 1
      result = Fq12.mul(five, five_inv)
      expected = Fq12.one(@fq12_modulus_coeffs)

      assert Fq12.eq?(result, expected), "5 * (1/5) should equal 1"
    end

    test "x^6 * x^6 = x^12 should reduce correctly" do
      # Create element representing x^6: [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]
      x6_coeffs = List.duplicate(Fq.zero(), 6) ++ [Fq.one()] ++ List.duplicate(Fq.zero(), 5)
      x6 = Fq12.new(x6_coeffs, @fq12_modulus_coeffs)

      # x^6 * x^6 = x^12, which should reduce to -2 + 2*x^6
      result = Fq12.mul(x6, x6)

      # Expected: [-2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0] (mod field_modulus)
      expected_coeffs = [
        # -2 at position 0
        Fq.neg(Fq.from_integer(2)),
        Fq.zero(),
        Fq.zero(),
        Fq.zero(),
        Fq.zero(),
        Fq.zero(),
        # 2 at position 6
        Fq.from_integer(2),
        Fq.zero(),
        Fq.zero(),
        Fq.zero(),
        Fq.zero(),
        Fq.zero()
      ]

      expected = Fq12.new(expected_coeffs, @fq12_modulus_coeffs)

      assert Fq12.eq?(result, expected), "x^6 * x^6 should reduce to -2 + 2*x^6"
    end

    test "complex polynomial multiplication matches py_ecc" do
      # Test case: A = [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      #            B = [4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      # Expected result from py_ecc: [4, 13, 28, 27, 18, 0, 0, 0, 0, 0, 0, 0]

      a_coeffs =
        [Fq.from_integer(1), Fq.from_integer(2), Fq.from_integer(3)] ++
          List.duplicate(Fq.zero(), 9)

      b_coeffs =
        [Fq.from_integer(4), Fq.from_integer(5), Fq.from_integer(6)] ++
          List.duplicate(Fq.zero(), 9)

      a = Fq12.new(a_coeffs, @fq12_modulus_coeffs)
      b = Fq12.new(b_coeffs, @fq12_modulus_coeffs)

      result = Fq12.mul(a, b)

      expected_coeffs =
        [
          Fq.from_integer(4),
          Fq.from_integer(13),
          Fq.from_integer(28),
          Fq.from_integer(27),
          Fq.from_integer(18)
        ] ++ List.duplicate(Fq.zero(), 7)

      expected = Fq12.new(expected_coeffs, @fq12_modulus_coeffs)

      assert Fq12.eq?(result, expected), "Complex multiplication should match py_ecc result"
    end

    test "multiplication requiring multiple reductions" do
      # Test case from py_ecc trace: A = [0]*10 + [1, 2], B = [0]*8 + [3, 0, 0, 4]
      # This will produce terms up to degree 22 that need reduction

      a_coeffs = List.duplicate(Fq.zero(), 10) ++ [Fq.from_integer(1), Fq.from_integer(2)]

      b_coeffs =
        List.duplicate(Fq.zero(), 8) ++
          [Fq.from_integer(3), Fq.zero(), Fq.zero(), Fq.from_integer(4)]

      a = Fq12.new(a_coeffs, @fq12_modulus_coeffs)
      b = Fq12.new(b_coeffs, @fq12_modulus_coeffs)

      result = Fq12.mul(a, b)

      # The exact expected result from py_ecc (after modular reduction):
      # [-12, -24, 0, -16, -32, 0, 6, 12, 0, 8, 16, 0] (all mod field_modulus)
      expected_coeffs = [
        # -12
        Fq.neg(Fq.from_integer(12)),
        # -24  
        Fq.neg(Fq.from_integer(24)),
        Fq.zero(),
        # -16
        Fq.neg(Fq.from_integer(16)),
        # -32
        Fq.neg(Fq.from_integer(32)),
        Fq.zero(),
        Fq.from_integer(6),
        Fq.from_integer(12),
        Fq.zero(),
        Fq.from_integer(8),
        Fq.from_integer(16),
        Fq.zero()
      ]

      expected = Fq12.new(expected_coeffs, @fq12_modulus_coeffs)

      assert Fq12.eq?(result, expected),
             "High-degree multiplication should match py_ecc reduction algorithm"
    end
  end

  describe "Fq12 field operations" do
    test "basic arithmetic operations" do
      # x = (1, 0, 0, ..., 0)
      x_coeffs = [1] ++ List.duplicate(0, 11)
      x = Fq12.from_integers(x_coeffs)

      # f = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
      f_coeffs = Enum.to_list(1..12)
      f = Fq12.from_integers(f_coeffs)

      # fpx = (2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
      fpx_coeffs = [2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
      fpx = Fq12.from_integers(fpx_coeffs)

      # one = 1
      one = Fq12.one()

      # assert x + f == fpx
      assert Fq12.eq?(Fq12.add(x, f), fpx)

      # assert f / f == one
      f_div_f = Fq12.field_div(f, f)
      assert Fq12.eq?(f_div_f, one)

      # assert one / f + x / f == (one + x) / f
      one_div_f = Fq12.field_div(one, f)
      x_div_f = Fq12.field_div(x, f)
      one_plus_x = Fq12.add(one, x)
      one_plus_x_div_f = Fq12.field_div(one_plus_x, f)

      assert Fq12.eq?(Fq12.add(one_div_f, x_div_f), one_plus_x_div_f)

      # assert one * f + x * f == (one + x) * f
      one_times_f = Fq12.mul(one, f)
      x_times_f = Fq12.mul(x, f)
      one_plus_x_times_f = Fq12.mul(one_plus_x, f)

      assert Fq12.eq?(Fq12.add(one_times_f, x_times_f), one_plus_x_times_f)

      # Test negative coefficients are positive
      neg_coeffs = List.duplicate(-1, 12)
      neg_fq12 = Fq12.from_integers(neg_coeffs)
      %{coeffs: coeffs} = neg_fq12

      coeffs
      |> Enum.map(&Fq.to_integer/1)
      |> Enum.each(fn z -> assert z > 0 end)
    end
  end

  describe "Fq field operations - known value tests" do
    test "basic arithmetic operations with specific values" do
      # Test values
      a = Fq.from_integer(123)
      b = Fq.from_integer(456)

      # Addition: 123 + 456 = 579
      assert Fq.to_integer(Fq.add(a, b)) == 579

      # Multiplication: 123 * 456 = 56088
      assert Fq.to_integer(Fq.mul(a, b)) == 56088

      # Subtraction: 123 - 456 (with modular arithmetic)
      expected_sub =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_454

      assert Fq.to_integer(Fq.sub(a, b)) == expected_sub

      # Squaring: 123 ** 2 = 15129
      assert Fq.to_integer(Fq.square(a)) == 15129
    end

    test "field modulus matches constants" do
      expected_modulus = Constants.field_modulus()
      assert Fq.modulus() == expected_modulus
    end

    test "negation operation" do
      b = Fq.from_integer(456)

      # -456 in field
      expected_neg =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_331

      assert Fq.to_integer(Fq.neg(b)) == expected_neg
    end

    test "zero and one elements" do
      assert Fq.to_integer(Fq.zero()) == 0
      assert Fq.to_integer(Fq.one()) == 1
    end

    test "large number multiplication" do
      large1 = Fq.from_integer(123_456_789_012_345_678_901_234_567_890)
      large2 = Fq.from_integer(987_654_321_098_765_432_109_876_543_210)
      # Expected result: 121932631137021795226185032733622923332237463801111263526900
      expected = 121_932_631_137_021_795_226_185_032_733_622_923_332_237_463_801_111_263_526_900
      assert Fq.to_integer(Fq.mul(large1, large2)) == expected
    end
  end

  # Helper function to generate random Fq2 elements
  defp random_fq2 do
    Fq2.new(Fq.random(), Fq.random())
  end
end
