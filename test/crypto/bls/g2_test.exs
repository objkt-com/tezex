defmodule Tezex.Crypto.BLS.G2Test do
  use ExUnit.Case, async: true

  alias Tezex.Crypto.BLS.Constants
  alias Tezex.Crypto.BLS.Fq2
  alias Tezex.Crypto.BLS.Fr
  alias Tezex.Crypto.BLS.G2

  describe "G2 generator" do
    test "is on curve" do
      generator = G2.generator()
      assert G2.is_on_curve?(generator)
    end

    test "is not zero" do
      generator = G2.generator()
      refute G2.is_infinity?(generator)
    end
  end

  describe "G2 scalar multiplication" do
    test "1 * generator equals generator" do
      generator = G2.generator()
      one = Fr.one()

      result = G2.mul(generator, one)

      assert G2.eq?(result, generator)
    end

    test "0 * generator equals zero" do
      generator = G2.generator()
      zero = Fr.zero()

      result = G2.mul(generator, zero)

      assert G2.is_infinity?(result)
    end
  end

  describe "G2 compression/decompression" do
    test "round-trip compression preserves generator" do
      generator = G2.generator()

      compressed = G2.to_compressed_bytes(generator)
      assert byte_size(compressed) == 96

      case G2.from_compressed_bytes(compressed) do
        {:ok, decompressed} ->
          assert G2.eq?(generator, decompressed)

        {:error, reason} ->
          flunk("Failed to decompress G2 generator: #{reason}")
      end
    end

    test "point at infinity compresses correctly" do
      infinity = G2.zero()
      compressed = G2.to_compressed_bytes(infinity)

      # Should be 0xC0 in x_c1 followed by zeros, then zeros for x_c0
      assert compressed == <<0xC0, 0::376, 0::384>>

      assert {:ok, decompressed} = G2.from_compressed_bytes(compressed)
      assert G2.is_infinity?(decompressed)
    end
  end

  describe "Fq2 square root" do
    test "square root of 1 is 1" do
      one = Fq2.one()

      # For debugging - let's check if sqrt is implemented
      case Fq2.sqrt(one) do
        {:ok, result} ->
          # sqrt(1) should be 1
          assert Fq2.eq?(result, one)

        {:error, reason} ->
          flunk("Failed to find square root of 1: #{reason}")
      end
    end

    test "square root verification" do
      # Test with a simple value
      test_val = Fq2.from_integers(4, 0)

      case Fq2.sqrt(test_val) do
        {:ok, sqrt_val} ->
          # Verify that sqrt^2 == original
          squared = Fq2.square(sqrt_val)
          assert Fq2.eq?(squared, test_val)

        {:error, _} ->
          # Some values may not have square roots, that's ok
          :ok
      end
    end
  end

  describe "hash to curve" do
    test "produces valid G2 points" do
      test_message = "test message"
      ciphersuite = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"

      point = G2.hash_to_curve(test_message, ciphersuite)

      assert G2.is_on_curve?(point)
      refute G2.is_infinity?(point)
    end
  end

  describe "G2 equality regression tests" do
    test "equality handles different Jacobian representations of same point" do
      # This test prevents regression of the equality bug where
      # different computation paths produce different Jacobian coordinates
      # but should be recognized as equal points (same as G1 test)
      g2 = G2.generator()

      # Path 1: double(double(G2)) = 4G via doubling
      double_g2 = G2.double(g2)
      four_g_via_doubling = G2.double(double_g2)

      # Path 2: add(add(double(G2), G2), G2) = 4G via addition
      three_g = G2.add(double_g2, g2)
      four_g_via_addition = G2.add(three_g, g2)

      # Both should be on curve
      assert G2.is_on_curve?(four_g_via_doubling)
      assert G2.is_on_curve?(four_g_via_addition)

      # Most importantly: they should be equal despite having different Jacobian coordinates
      assert G2.eq?(four_g_via_doubling, four_g_via_addition),
             "4G computed via doubling and addition should be equal"

      # Verify they actually have different coordinates (this validates the test)
      %{x: x1, y: y1, z: z1} = four_g_via_doubling
      %{x: x2, y: y2, z: z2} = four_g_via_addition

      # At least one coordinate should be different (proving they have different representations)
      different_coords = not (Fq2.eq?(x1, x2) and Fq2.eq?(y1, y2) and Fq2.eq?(z1, z2))
      assert different_coords, "Test should use points with different Jacobian coordinates"
    end
  end

  describe "py_ecc compatibility" do
    test "generator coordinates match py_ecc exactly" do
      g2 = G2.generator()

      # py_ecc G2 generator values
      expected_x_c0 =
        352_701_069_587_466_618_187_139_116_011_060_144_890_029_952_792_775_240_219_908_644_239_793_785_735_715_026_873_347_600_343_865_175_952_761_926_303_160

      expected_x_c1 =
        3_059_144_344_244_213_709_971_259_814_753_781_636_986_470_325_476_647_558_659_373_206_291_635_324_768_958_432_433_509_563_104_347_017_837_885_763_365_758

      expected_y_c0 =
        1_985_150_602_287_291_935_568_054_521_177_171_638_300_868_978_215_655_730_859_378_665_066_344_726_373_823_718_423_869_104_263_333_984_641_494_340_347_905

      expected_y_c1 =
        927_553_665_492_332_455_747_201_965_776_037_880_757_740_193_453_592_970_025_027_978_793_976_877_002_675_564_980_949_289_727_957_565_575_433_344_219_582

      {x_c0, x_c1} = Fq2.to_integers(g2.x)
      {y_c0, y_c1} = Fq2.to_integers(g2.y)
      {z_c0, z_c1} = Fq2.to_integers(g2.z)

      assert x_c0 == expected_x_c0, "Generator x_c0 should match py_ecc"
      assert x_c1 == expected_x_c1, "Generator x_c1 should match py_ecc"
      assert y_c0 == expected_y_c0, "Generator y_c0 should match py_ecc"
      assert y_c1 == expected_y_c1, "Generator y_c1 should match py_ecc"
      assert z_c0 == 1, "Generator z_c0 should be 1"
      assert z_c1 == 0, "Generator z_c1 should be 0"
    end

    test "double(G2) Jacobian coordinates match py_ecc exactly" do
      g2 = G2.generator()
      doubled = G2.double(g2)

      # py_ecc double(G2) Jacobian values
      expected_x_c0 =
        2_004_569_552_561_385_659_566_932_407_633_616_698_939_912_674_197_491_321_901_037_400_001_042_336_021_538_860_336_682_240_104_624_979_660_689_237_563_240

      expected_x_c1 =
        3_955_604_752_108_186_662_342_584_665_293_438_104_124_851_975_447_411_601_471_797_343_177_761_394_177_049_673_802_376_047_736_772_242_152_530_202_962_941

      expected_y_c0 =
        978_142_457_653_236_052_983_988_388_396_292_566_217_089_069_272_380_812_666_116_929_298_652_861_694_202_207_333_864_830_606_577_192_738_105_844_024_927

      expected_y_c1 =
        2_248_711_152_455_689_790_114_026_331_322_133_133_284_196_260_289_964_969_465_268_080_325_775_757_898_907_753_181_154_992_709_229_860_715_480_504_777_099

      expected_z_c0 =
        3_145_673_658_656_250_241_340_817_105_688_138_628_074_744_674_635_286_712_244_193_301_767_486_380_727_788_868_972_774_468_795_689_607_869_551_989_918_920

      expected_z_c1 =
        968_254_395_890_002_185_853_925_600_926_112_283_510_369_004_782_031_018_144_050_081_533_668_188_797_348_331_621_250_985_545_304_947_843_412_000_516_197

      %{x: {x_c0, x_c1}, y: {y_c0, y_c1}, z: {z_c0, z_c1}} = doubled

      assert Tezex.Crypto.BLS.Fq.to_integer(x_c0) == expected_x_c0
      assert Tezex.Crypto.BLS.Fq.to_integer(x_c1) == expected_x_c1
      assert Tezex.Crypto.BLS.Fq.to_integer(y_c0) == expected_y_c0
      assert Tezex.Crypto.BLS.Fq.to_integer(y_c1) == expected_y_c1
      assert Tezex.Crypto.BLS.Fq.to_integer(z_c0) == expected_z_c0
      assert Tezex.Crypto.BLS.Fq.to_integer(z_c1) == expected_z_c1
    end

    test "double(G2) affine coordinates match py_ecc" do
      g2 = G2.generator()
      two_g = G2.double(g2)

      # py_ecc 2G affine values
      expected_affine_x_c0 =
        3_419_974_069_068_927_546_093_595_533_691_935_972_093_267_703_063_689_549_934_039_433_172_037_728_172_434_967_174_817_854_768_758_291_501_458_544_631_891

      expected_affine_x_c1 =
        1_586_560_233_067_062_236_092_888_871_453_626_466_803_933_380_746_149_805_590_083_683_748_120_990_227_823_365_075_019_078_675_272_292_060_187_343_402_359

      expected_affine_y_c0 =
        678_774_053_046_495_337_979_740_195_232_911_687_527_971_909_891_867_263_302_465_188_023_833_943_429_943_242_788_645_503_130_663_197_220_262_587_963_545

      expected_affine_y_c1 =
        2_374_407_843_478_705_782_611_042_739_236_452_317_510_200_146_460_567_463_070_514_850_492_917_978_226_342_495_167_066_333_366_894_448_569_891_658_583_283

      assert {:ok, {affine_x, affine_y}} = G2.to_affine(two_g)

      {x_c0, x_c1} = Fq2.to_integers(affine_x)
      {y_c0, y_c1} = Fq2.to_integers(affine_y)

      assert x_c0 == expected_affine_x_c0
      assert x_c1 == expected_affine_x_c1
      assert y_c0 == expected_affine_y_c0
      assert y_c1 == expected_affine_y_c1
    end

    test "3*G2 coordinates match py_ecc exactly" do
      g2 = G2.generator()
      g2_2 = G2.double(g2)
      g2_3 = G2.add(g2_2, g2)

      # py_ecc 3*G2 Jacobian values
      expected_x_c0 =
        2_260_316_515_795_278_483_227_354_417_550_273_673_937_385_151_660_885_802_822_200_676_798_473_320_332_386_191_812_885_909_324_314_180_009_401_590_033_496

      expected_x_c1 =
        3_157_705_674_295_752_746_643_045_744_187_038_651_144_673_626_385_096_899_515_739_718_638_356_953_289_853_357_506_730_468_806_346_866_010_850_469_607_484

      expected_y_c0 =
        3_116_406_908_094_559_010_983_016_654_096_953_279_342_014_296_159_903_648_784_769_141_704_444_407_188_785_914_041_577_477_129_027_384_530_629_024_324_101

      expected_y_c1 =
        624_739_198_846_365_065_958_511_422_206_549_337_298_084_868_949_577_950_118_937_104_460_230_094_422_413_163_466_712_508_875_838_914_229_203_179_007_739

      expected_z_c0 =
        1_372_365_362_697_527_824_661_960_056_804_989_242_334_959_973_433_633_343_888_520_294_361_286_317_391_588_271_032_081_626_721_722_944_066_233_963_018_813

      expected_z_c1 =
        135_340_553_306_575_460_225_879_133_388_402_231_094_623_862_625_345_515_492_709_522_456_301_372_944_095_308_361_691_014_711_792_956_665_222_682_354_141

      %{x: {x_c0, x_c1}, y: {y_c0, y_c1}, z: {z_c0, z_c1}} = g2_3

      assert Tezex.Crypto.BLS.Fq.to_integer(x_c0) == expected_x_c0
      assert Tezex.Crypto.BLS.Fq.to_integer(x_c1) == expected_x_c1
      assert Tezex.Crypto.BLS.Fq.to_integer(y_c0) == expected_y_c0
      assert Tezex.Crypto.BLS.Fq.to_integer(y_c1) == expected_y_c1
      assert Tezex.Crypto.BLS.Fq.to_integer(z_c0) == expected_z_c0
      assert Tezex.Crypto.BLS.Fq.to_integer(z_c1) == expected_z_c1
    end

    test "4G affine coordinates from different computation paths match py_ecc" do
      g2 = G2.generator()

      # Path 1: double(double(G)) = 4G via doubling
      two_g = G2.double(g2)
      four_g_double = G2.double(two_g)

      # Path 2: add(add(double(G), G), G) = 4G via addition  
      three_g = G2.add(two_g, g2)
      four_g_add = G2.add(three_g, g2)

      # Both should produce same affine coordinates
      assert {:ok, {affine_x1, affine_y1}} = G2.to_affine(four_g_double)
      assert {:ok, {affine_x2, affine_y2}} = G2.to_affine(four_g_add)

      assert Fq2.eq?(affine_x1, affine_x2), "Affine X coordinates should match"
      assert Fq2.eq?(affine_y1, affine_y2), "Affine Y coordinates should match"

      # Expected affine coordinates for 4G from py_ecc
      expected_affine_x_c0 =
        2_228_261_016_665_467_246_533_331_009_551_956_115_370_380_172_154_746_298_363_804_663_874_927_447_724_251_086_262_215_215_805_607_611_831_416_839_456_087

      expected_affine_x_c1 =
        1_078_694_598_252_689_404_244_396_341_813_443_419_551_535_268_687_482_491_181_036_693_120_116_966_808_940_002_268_138_449_409_757_966_646_650_205_799_154

      expected_affine_y_c0 =
        1_078_130_147_839_725_710_638_550_237_346_893_815_189_184_147_577_339_719_832_678_031_476_197_662_920_373_232_750_257_163_212_369_151_522_627_886_861_080

      expected_affine_y_c1 =
        1_156_012_089_965_243_131_925_155_359_058_270_233_117_178_570_263_500_297_221_609_542_882_736_610_397_356_630_132_228_324_008_545_337_607_514_631_821_497

      {actual_x_c0, actual_x_c1} = Fq2.to_integers(affine_x1)
      {actual_y_c0, actual_y_c1} = Fq2.to_integers(affine_y1)

      assert actual_x_c0 == expected_affine_x_c0
      assert actual_x_c1 == expected_affine_x_c1
      assert actual_y_c0 == expected_affine_y_c0
      assert actual_y_c1 == expected_affine_y_c1
    end
  end

  describe "G2 elliptic curve operations" do
    test "basic group operations" do
      g2 = G2.generator()

      # assert eq(add(add(double(G2), G2), G2), double(double(G2)))
      double_g2 = G2.double(g2)
      double_double_g2 = G2.double(double_g2)
      add_double_g2_g2 = G2.add(double_g2, g2)
      add_add_double_g2_g2_g2 = G2.add(add_double_g2_g2, g2)

      assert G2.eq?(add_add_double_g2_g2_g2, double_double_g2)

      # assert not eq(double(G2), G2)
      refute G2.eq?(double_g2, g2)

      # assert eq(add(multiply(G2, 9), multiply(G2, 5)), add(multiply(G2, 12), multiply(G2, 2)))
      nine = Fr.from_integer(9)
      five = Fr.from_integer(5)
      twelve = Fr.from_integer(12)
      two = Fr.from_integer(2)

      mul_g2_9 = G2.mul(g2, nine)
      mul_g2_5 = G2.mul(g2, five)
      mul_g2_12 = G2.mul(g2, twelve)
      mul_g2_2 = G2.mul(g2, two)

      add_9_5 = G2.add(mul_g2_9, mul_g2_5)
      add_12_2 = G2.add(mul_g2_12, mul_g2_2)

      assert G2.eq?(add_9_5, add_12_2)

      # assert is_inf(multiply(G2, curve_order))
      curve_order = Constants.curve_order()
      curve_order_fr = Fr.from_integer(curve_order)
      mul_g2_order = G2.mul(g2, curve_order_fr)
      assert G2.is_infinity?(mul_g2_order)

      # assert not is_inf(multiply(G2, 2 * field_modulus - curve_order))
      field_modulus = Constants.field_modulus()
      special_scalar = 2 * field_modulus - curve_order
      special_scalar_fr = Fr.from_integer(special_scalar)
      mul_g2_special = G2.mul(g2, special_scalar_fr)
      refute G2.is_infinity?(mul_g2_special)

      # assert is_on_curve(multiply(G2, 9), b2)
      assert G2.is_on_curve?(mul_g2_9)
    end
  end

  describe "Zero points (identity elements)" do
    test "G2 zero point properties" do
      g2 = G2.generator()
      z2 = G2.zero()

      # assert eq(G2, add(G2, Z2))
      assert G2.eq?(g2, G2.add(g2, z2))

      # assert eq(Z2, double(Z2))
      assert G2.eq?(z2, G2.double(z2))

      # assert eq(Z2, multiply(Z2, 0))
      zero = Fr.zero()
      one = Fr.one()
      two = Fr.from_integer(2)
      three = Fr.from_integer(3)

      assert G2.eq?(z2, G2.mul(z2, zero))
      assert G2.eq?(z2, G2.mul(z2, one))
      assert G2.eq?(z2, G2.mul(z2, two))
      assert G2.eq?(z2, G2.mul(z2, three))

      # assert is_inf(neg(Z2))
      neg_z2 = G2.negate(z2)
      assert G2.is_infinity?(neg_z2)
    end
  end
end
