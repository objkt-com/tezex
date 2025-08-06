defmodule Tezex.Crypto.BLS.G1Test do
  use ExUnit.Case, async: true
  import Bitwise

  alias Tezex.Crypto.BLS.Constants
  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.BLS.Fr
  alias Tezex.Crypto.BLS.G1

  describe "G1 generator" do
    test "has correct coordinates matching py_ecc" do
      generator = G1.generator()

      assert {:ok, {x, y}} = G1.to_affine(generator)

      x_int = Fq.to_integer(x)
      y_int = Fq.to_integer(y)

      # These values come from py_ecc.optimized_bls12_381.G1
      expected_x =
        3_685_416_753_713_387_016_781_088_315_183_077_757_961_620_795_782_546_409_894_578_378_688_607_592_378_376_318_836_054_947_676_345_821_548_104_185_464_507

      expected_y =
        1_339_506_544_944_476_473_020_471_379_941_921_221_584_933_875_938_349_620_426_543_736_416_511_423_956_333_506_472_724_655_353_366_534_992_391_756_441_569

      assert x_int == expected_x
      assert y_int == expected_y
    end

    test "is on curve" do
      generator = G1.generator()
      assert G1.is_on_curve?(generator)
    end

    test "is not zero" do
      generator = G1.generator()
      refute G1.is_infinity?(generator)
    end
  end

  describe "G1 scalar multiplication" do
    test "1 * generator equals generator" do
      generator = G1.generator()
      one = Fr.one()

      result = G1.mul(generator, one)

      assert G1.eq?(result, generator)
    end

    test "0 * generator equals zero" do
      generator = G1.generator()
      zero = Fr.zero()

      result = G1.mul(generator, zero)

      assert G1.is_infinity?(result)
    end

    test "2 * generator equals generator + generator" do
      generator = G1.generator()
      two = Fr.from_integer(2)

      double_via_mul = G1.mul(generator, two)
      double_via_add = G1.add(generator, generator)

      assert G1.eq?(double_via_mul, double_via_add)
    end
  end

  describe "G1 compression/decompression" do
    test "round-trip compression preserves point" do
      generator = G1.generator()

      compressed = G1.to_compressed_bytes(generator)
      assert byte_size(compressed) == 48

      assert {:ok, decompressed} = G1.from_compressed_bytes(compressed)
      assert G1.eq?(generator, decompressed)
    end

    test "compressed generator has expected format" do
      generator = G1.generator()
      compressed = G1.to_compressed_bytes(generator)

      # First byte should have compression flag set (0x80)
      <<first_byte, _rest::binary>> = compressed
      assert (first_byte &&& 0x80) != 0
    end

    test "point at infinity compresses correctly" do
      infinity = G1.zero()
      compressed = G1.to_compressed_bytes(infinity)

      # Should be 0xC0 followed by zeros
      assert compressed == <<0xC0>> <> <<0::376>>

      assert {:ok, decompressed} = G1.from_compressed_bytes(compressed)
      assert G1.is_infinity?(decompressed)
    end
  end

  describe "Fr field operations" do
    test "uses big-endian encoding" do
      # Test that Fr.from_integer(1) produces big-endian encoding
      one = Fr.from_integer(1)
      assert one == <<0::248, 1::8>>

      # Test conversion back
      assert Fr.to_integer(one) == 1
    end

    test "from_bytes handles big-endian correctly" do
      # Big-endian representation of 1
      bytes = <<0::248, 1::8>>
      assert {:ok, fr} = Fr.from_bytes(bytes)
      assert Fr.to_integer(fr) == 1
    end
  end

  describe "G1 equality regression tests" do
    test "equality handles different Jacobian representations of same point" do
      # This test prevents regression of the equality bug where
      # different computation paths to 4G produced different Jacobian coordinates
      # but should be recognized as equal points
      g1 = G1.generator()

      # Path 1: double(double(G1)) = 4G via doubling
      double_g1 = G1.double(g1)
      four_g_via_doubling = G1.double(double_g1)

      # Path 2: add(add(double(G1), G1), G1) = 4G via addition  
      three_g = G1.add(double_g1, g1)
      four_g_via_addition = G1.add(three_g, g1)

      # Both should be on curve
      assert G1.is_on_curve?(four_g_via_doubling)
      assert G1.is_on_curve?(four_g_via_addition)

      # Most importantly: they should be equal despite having different Jacobian coordinates
      assert G1.eq?(four_g_via_doubling, four_g_via_addition),
             "4G computed via doubling and addition should be equal"

      # Verify they actually have different coordinates (this validates the test)
      %{x: x1, y: y1, z: z1} = four_g_via_doubling
      %{x: x2, y: y2, z: z2} = four_g_via_addition

      # At least one coordinate should be different (proving they have different representations)
      different_coords = not (Fq.eq?(x1, x2) and Fq.eq?(y1, y2) and Fq.eq?(z1, z2))
      assert different_coords, "Test should use points with different Jacobian coordinates"
    end
  end

  describe "py_ecc compatibility" do
    test "scalar multiplication with scalar 5 matches py_ecc" do
      # Expected result from py_ecc for 5 * G1
      py_ecc_result_x =
        2_601_793_266_141_653_880_357_945_339_922_727_723_793_268_013_331_457_916_525_213_050_197_274_797_722_760_296_318_099_993_752_923_714_935_161_798_464_476

      py_ecc_result_y =
        3_498_096_627_312_022_583_321_348_410_616_510_759_186_251_088_555_060_790_999_813_363_211_667_535_344_132_702_692_445_545_590_448_314_959_259_020_805_858

      seed = <<5::size(256)>>
      {:ok, fr_element} = Fr.from_bytes(seed)

      generator = G1.generator()
      result = G1.mul(generator, fr_element)
      {:ok, {x_aff, y_aff}} = G1.to_affine(result)

      x_int = Fq.to_integer(x_aff)
      y_int = Fq.to_integer(y_aff)

      assert x_int == py_ecc_result_x, "Scalar mult result X should match py_ecc"
      assert y_int == py_ecc_result_y, "Scalar mult result Y should match py_ecc"
    end

    test "compressed public key matches py_ecc format" do
      # py_ecc compressed pubkey for privkey=5
      expected_compressed =
        <<0xB0, 0xE7, 0x79, 0x1F, 0xB9, 0x72, 0xFE, 0x01, 0x41, 0x59, 0xAA, 0x33, 0xA9, 0x86,
          0x22, 0xDA, 0x3C, 0xDC, 0x98, 0xFF, 0x70, 0x79, 0x65, 0xE5, 0x36, 0xD8, 0x63, 0x6B,
          0x5F, 0xCC, 0x5A, 0xC7, 0xA9, 0x1A, 0x8C, 0x46, 0xE5, 0x9A, 0x00, 0xDC, 0xA5, 0x75,
          0xAF, 0x0F, 0x18, 0xFB, 0x13, 0xDC>>

      seed = <<5::size(256)>>
      {:ok, fr_element} = Fr.from_bytes(seed)

      generator = G1.generator()
      result = G1.mul(generator, fr_element)
      compressed = G1.to_compressed_bytes(result)

      assert compressed == expected_compressed, "Compressed format should match py_ecc"
    end
  end

  describe "G1 elliptic curve operations" do
    test "basic group operations" do
      g1 = G1.generator()

      # assert eq(add(add(double(G1), G1), G1), double(double(G1)))
      double_g1 = G1.double(g1)
      double_double_g1 = G1.double(double_g1)
      add_double_g1_g1 = G1.add(double_g1, g1)
      add_add_double_g1_g1_g1 = G1.add(add_double_g1_g1, g1)

      assert G1.eq?(add_add_double_g1_g1_g1, double_double_g1)

      # assert not eq(double(G1), G1)
      refute G1.eq?(double_g1, g1)

      # assert eq(add(multiply(G1, 9), multiply(G1, 5)), add(multiply(G1, 12), multiply(G1, 2)))
      nine = Fr.from_integer(9)
      five = Fr.from_integer(5)
      twelve = Fr.from_integer(12)
      two = Fr.from_integer(2)

      mul_g1_9 = G1.mul(g1, nine)
      mul_g1_5 = G1.mul(g1, five)
      mul_g1_12 = G1.mul(g1, twelve)
      mul_g1_2 = G1.mul(g1, two)

      add_9_5 = G1.add(mul_g1_9, mul_g1_5)
      add_12_2 = G1.add(mul_g1_12, mul_g1_2)

      assert G1.eq?(add_9_5, add_12_2)

      # assert is_inf(multiply(G1, curve_order))
      curve_order = Constants.curve_order()
      curve_order_fr = Fr.from_integer(curve_order)
      mul_g1_order = G1.mul(g1, curve_order_fr)
      assert G1.is_infinity?(mul_g1_order)
    end
  end

  describe "Zero points (identity elements)" do
    test "G1 zero point properties" do
      g1 = G1.generator()
      z1 = G1.zero()

      # assert eq(G1, add(G1, Z1))
      assert G1.eq?(g1, G1.add(g1, z1))

      # assert eq(Z1, double(Z1))
      assert G1.eq?(z1, G1.double(z1))

      # assert eq(Z1, multiply(Z1, 0))
      zero = Fr.zero()
      one = Fr.one()
      two = Fr.from_integer(2)
      three = Fr.from_integer(3)

      assert G1.eq?(z1, G1.mul(z1, zero))
      assert G1.eq?(z1, G1.mul(z1, one))
      assert G1.eq?(z1, G1.mul(z1, two))
      assert G1.eq?(z1, G1.mul(z1, three))

      # assert is_inf(neg(Z1))
      neg_z1 = G1.negate(z1)
      assert G1.is_infinity?(neg_z1)
    end
  end

  describe "Coordinate system operations" do
    test "projective coordinate doubling produces known values" do
      # Expected Jacobian coordinates for doubled generator
      expected_x =
        904_218_658_502_494_312_590_159_247_105_554_874_787_512_476_566_126_303_635_147_587_402_923_829_641_584_622_770_449_558_420_966_780_868_207_684_298_157

      expected_y =
        3_215_784_584_818_841_779_393_380_451_963_501_913_485_474_208_604_528_267_666_791_755_940_205_624_806_737_197_312_591_247_682_567_521_662_969_376_111_781

      expected_z =
        645_039_760_431_336_131_708_729_805_154_580_111_675_108_263_123_058_424_684_373_273_230_141_681_090_362_840_405_422_204_836_635_344_492_771_939_114_786

      # Expected affine coordinates after normalization
      expected_normalized_x =
        838_589_206_289_216_005_799_424_730_305_866_328_161_735_431_124_665_289_961_769_162_861_615_689_790_485_775_997_575_391_185_127_590_486_775_437_397_838

      expected_normalized_y =
        3_450_209_970_729_243_429_733_164_009_999_191_867_485_184_320_918_914_219_895_632_678_707_687_208_996_709_678_363_578_245_114_137_957_452_475_385_814_312

      # Test our doubling produces the correct Jacobian coordinates
      generator = G1.generator()
      doubled = G1.double(generator)
      %{x: x, y: y, z: z} = doubled

      x_int = Fq.to_integer(x)
      y_int = Fq.to_integer(y)
      z_int = Fq.to_integer(z)

      assert x_int == expected_x, "Jacobian X should match known value"
      assert y_int == expected_y, "Jacobian Y should match known value"
      assert z_int == expected_z, "Jacobian Z should match known value"

      # Test our projective coordinate affine conversion
      {:ok, {affine_x, affine_y}} = G1.to_affine(doubled)
      affine_x_int = Fq.to_integer(affine_x)
      affine_y_int = Fq.to_integer(affine_y)

      # Should match normalized coordinates
      assert affine_x_int == expected_normalized_x, "Affine X should match known value"
      assert affine_y_int == expected_normalized_y, "Affine Y should match known value"
    end
  end
end
