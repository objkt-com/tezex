defmodule Tezex.Crypto.BLS.HashToCurveMappingTest do
  use ExUnit.Case, async: true

  alias Tezex.Crypto.BLS.Fq2
  alias Tezex.Crypto.BLS.G2

  describe "SSWU mapping operations" do
    test "SSWU mapping for specific field element u0" do
      # Input field element u0 from hash_to_field_FQ2("hello world", 2, dst)
      u0_c0 =
        1_717_481_801_022_890_320_930_535_539_684_145_078_363_416_826_664_358_709_416_530_433_123_807_602_906_499_236_696_635_892_172_619_530_864_997_493_102_515

      u0_c1 =
        1_687_859_148_152_866_701_283_814_945_283_565_263_051_278_093_529_837_438_184_411_703_051_446_645_270_323_793_737_296_154_376_182_401_617_592_571_421_593

      u0 = Fq2.from_integers(u0_c0, u0_c1)

      # Expected SSWU(u0) result
      expected_x_c0 =
        796_173_875_720_834_253_623_727_506_271_078_041_020_251_392_772_031_672_345_317_992_429_015_938_707_504_145_184_699_842_548_681_111_121_477_231_464_588

      expected_x_c1 =
        2_553_240_928_850_692_148_144_609_726_821_978_673_910_622_315_327_992_197_547_050_968_824_001_489_123_743_897_267_269_834_754_689_946_017_196_982_133_401

      expected_y_c0 =
        2_309_192_382_432_807_183_166_084_529_647_111_454_597_739_575_294_565_093_368_416_237_116_772_620_221_902_878_563_567_248_863_546_919_357_777_429_902_675

      expected_y_c1 =
        2_586_493_671_439_743_965_770_770_303_452_682_393_515_563_815_845_127_441_996_901_006_879_933_639_046_896_211_788_453_535_264_525_976_650_333_670_026_608

      expected_z_c0 =
        809_500_295_226_557_698_756_926_798_397_199_118_323_607_410_412_494_527_267_471_140_176_137_427_791_063_365_262_052_291_197_955_969_487_397_529_159_432

      expected_z_c1 =
        3_684_344_747_470_531_207_307_271_375_680_124_786_338_931_052_574_163_313_513_438_459_614_267_363_603_552_283_607_329_320_143_023_358_132_871_525_346_032

      # Apply SSWU mapping
      {actual_x, actual_y, actual_z} = G2.sswu_map(u0)

      # Extract coefficients and convert to integers
      {actual_x_c0, actual_x_c1} = actual_x
      {actual_y_c0, actual_y_c1} = actual_y
      {actual_z_c0, actual_z_c1} = actual_z

      actual_x_c0_int = :binary.decode_unsigned(actual_x_c0)
      actual_x_c1_int = :binary.decode_unsigned(actual_x_c1)
      actual_y_c0_int = :binary.decode_unsigned(actual_y_c0)
      actual_y_c1_int = :binary.decode_unsigned(actual_y_c1)
      actual_z_c0_int = :binary.decode_unsigned(actual_z_c0)
      actual_z_c1_int = :binary.decode_unsigned(actual_z_c1)

      assert actual_x_c0_int == expected_x_c0
      assert actual_x_c1_int == expected_x_c1
      assert actual_y_c0_int == expected_y_c0
      assert actual_y_c1_int == expected_y_c1
      assert actual_z_c0_int == expected_z_c0
      assert actual_z_c1_int == expected_z_c1
    end

    test "SSWU mapping for simple field element (1, 0)" do
      # Simple test case: (1, 0)
      u = Fq2.from_integers(1, 0)

      # Expected SSWU result
      expected_x_c0 =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_558_775

      expected_x_c1 = 5060

      expected_y_c0 =
        1_347_507_234_798_921_329_944_701_265_542_592_282_430_463_344_696_112_603_091_539_605_429_516_992_934_832_530_571_627_687_441_447_322_864_595_111_169_093

      expected_y_c1 =
        3_260_065_998_889_756_212_591_550_323_019_334_687_872_981_459_637_068_827_486_240_396_953_606_841_488_756_160_755_458_572_297_306_998_566_838_745_359_909

      expected_z_c0 = 720

      expected_z_c1 =
        4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_547

      # Apply SSWU mapping
      {actual_x, actual_y, actual_z} = G2.sswu_map(u)

      # Extract coefficients and convert to integers
      {actual_x_c0, actual_x_c1} = actual_x
      {actual_y_c0, actual_y_c1} = actual_y
      {actual_z_c0, actual_z_c1} = actual_z

      actual_x_c0_int = :binary.decode_unsigned(actual_x_c0)
      actual_x_c1_int = :binary.decode_unsigned(actual_x_c1)
      actual_y_c0_int = :binary.decode_unsigned(actual_y_c0)
      actual_y_c1_int = :binary.decode_unsigned(actual_y_c1)
      actual_z_c0_int = :binary.decode_unsigned(actual_z_c0)
      actual_z_c1_int = :binary.decode_unsigned(actual_z_c1)

      assert actual_x_c0_int == expected_x_c0
      assert actual_x_c1_int == expected_x_c1
      assert actual_y_c0_int == expected_y_c0
      assert actual_y_c1_int == expected_y_c1
      assert actual_z_c0_int == expected_z_c0
      assert actual_z_c1_int == expected_z_c1
    end
  end

  describe "Isogeny mapping operations" do
    test "isogeny mapping for SSWU result" do
      # SSWU(u0) input coordinates
      x =
        Fq2.from_integers(
          796_173_875_720_834_253_623_727_506_271_078_041_020_251_392_772_031_672_345_317_992_429_015_938_707_504_145_184_699_842_548_681_111_121_477_231_464_588,
          2_553_240_928_850_692_148_144_609_726_821_978_673_910_622_315_327_992_197_547_050_968_824_001_489_123_743_897_267_269_834_754_689_946_017_196_982_133_401
        )

      y =
        Fq2.from_integers(
          2_309_192_382_432_807_183_166_084_529_647_111_454_597_739_575_294_565_093_368_416_237_116_772_620_221_902_878_563_567_248_863_546_919_357_777_429_902_675,
          2_586_493_671_439_743_965_770_770_303_452_682_393_515_563_815_845_127_441_996_901_006_879_933_639_046_896_211_788_453_535_264_525_976_650_333_670_026_608
        )

      z =
        Fq2.from_integers(
          809_500_295_226_557_698_756_926_798_397_199_118_323_607_410_412_494_527_267_471_140_176_137_427_791_063_365_262_052_291_197_955_969_487_397_529_159_432,
          3_684_344_747_470_531_207_307_271_375_680_124_786_338_931_052_574_163_313_513_438_459_614_267_363_603_552_283_607_329_320_143_023_358_132_871_525_346_032
        )

      # Expected iso_map_G2 result
      expected_x_c0 =
        3_730_664_267_803_065_519_618_473_115_339_978_425_435_001_599_053_657_516_966_273_455_168_703_835_273_385_086_642_066_111_321_238_676_472_873_550_507_039

      expected_x_c1 =
        1_932_440_596_784_524_961_460_414_449_764_135_756_352_604_187_345_853_799_388_230_578_663_492_691_730_253_677_451_536_899_503_095_193_998_583_157_737_099

      expected_y_c0 =
        1_656_072_553_096_042_706_776_461_214_075_085_543_862_859_506_917_151_958_604_436_876_295_264_117_186_425_009_932_841_051_353_229_290_421_096_634_314_976

      expected_y_c1 =
        2_089_695_700_261_254_513_897_468_258_954_057_892_839_808_228_112_975_110_805_050_045_020_610_872_870_988_769_385_835_380_007_831_958_320_430_051_424_747

      expected_z_c0 =
        662_252_190_560_844_014_192_464_224_524_991_544_006_079_962_628_184_881_423_967_610_720_178_819_254_590_922_389_857_451_430_147_824_546_612_699_622_552

      expected_z_c1 =
        2_070_086_394_022_424_304_750_141_371_165_332_799_051_026_006_317_898_229_867_514_783_937_637_466_152_146_237_099_451_683_820_803_245_921_772_054_002_608

      # Apply isogeny mapping
      {actual_x, actual_y, actual_z} = G2.iso_map_g2(x, y, z)

      # Extract coefficients and convert to integers
      {actual_x_c0, actual_x_c1} = actual_x
      {actual_y_c0, actual_y_c1} = actual_y
      {actual_z_c0, actual_z_c1} = actual_z

      actual_x_c0_int = :binary.decode_unsigned(actual_x_c0)
      actual_x_c1_int = :binary.decode_unsigned(actual_x_c1)
      actual_y_c0_int = :binary.decode_unsigned(actual_y_c0)
      actual_y_c1_int = :binary.decode_unsigned(actual_y_c1)
      actual_z_c0_int = :binary.decode_unsigned(actual_z_c0)
      actual_z_c1_int = :binary.decode_unsigned(actual_z_c1)

      assert actual_x_c0_int == expected_x_c0
      assert actual_x_c1_int == expected_x_c1
      assert actual_y_c0_int == expected_y_c0
      assert actual_y_c1_int == expected_y_c1
      assert actual_z_c0_int == expected_z_c0
      assert actual_z_c1_int == expected_z_c1
    end
  end
end
