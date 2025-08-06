defmodule Tezex.Crypto.BLS.HashToFieldTest do
  @moduledoc """
  Test hash-to-field implementation against known values
  """

  use ExUnit.Case
  alias Tezex.Crypto.BLS.G2
  alias Tezex.Crypto.BLS.HashToField

  describe "expand_message_xmd" do
    test "produces correct result for 32 bytes" do
      message = "hello world"
      dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

      result = HashToField.expand_message_xmd(message, dst, 32)

      # Expected result
      expected = "15f4bab703bacbb4725f88d1dceebd8d941cccd4e78d66ce1e271d3078e3c5e3"
      actual = Base.encode16(result, case: :lower)

      assert actual == expected, "expand_message_xmd should produce correct result for 32 bytes"
    end

    test "produces correct result for 256 bytes" do
      message = "hello world"
      dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

      result = HashToField.expand_message_xmd(message, dst, 256)

      # Expected first 64 bytes
      expected_first_64 =
        "05b218499b13a8c18014761ff123e27dc065772e666777698b2fa50993d4ee9e51ca6a11fb19730bda59e684533593ab9833842e69d0ebc0231d25038d72b6b1"

      actual_first_64 = Base.encode16(binary_part(result, 0, 64), case: :lower)

      assert byte_size(result) == 256

      assert actual_first_64 == expected_first_64,
             "expand_message_xmd should produce correct first 64 bytes"
    end

    test "works with various test vectors" do
      # Test vector 1: empty message
      result1 = HashToField.expand_message_xmd("", "QUUX-V01-CS02-with-expander-SHA256-128", 32)
      # Add expected value when we verify it works
      assert byte_size(result1) == 32

      # Test vector 2: different DST
      result2 =
        HashToField.expand_message_xmd("abc", "QUUX-V01-CS02-with-expander-SHA256-128", 32)

      assert byte_size(result2) == 32

      # Results should be different
      refute result1 == result2
    end
  end

  describe "hash_to_field_fq2" do
    test "produces correct result for hello world with count=1" do
      message = "hello world"
      dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

      result = HashToField.hash_to_field_fq2(message, 1, dst)

      assert length(result) == 1

      # Expected values
      expected_c0 =
        3_953_521_847_463_685_842_027_004_280_720_592_171_087_789_117_488_196_218_495_143_707_177_230_643_750_427_891_830_749_563_649_524_744_212_399_943_579_710

      expected_c1 =
        3_055_054_897_935_053_448_916_591_188_660_263_956_389_391_216_799_965_250_549_689_108_207_704_046_646_708_235_167_491_387_016_572_797_962_721_328_341_549

      {actual_c0, actual_c1} = Enum.at(result, 0)
      actual_c0_int = :binary.decode_unsigned(actual_c0)
      actual_c1_int = :binary.decode_unsigned(actual_c1)

      assert actual_c0_int == expected_c0
      assert actual_c1_int == expected_c1
    end

    test "produces correct result for hello world with count=2" do
      message = "hello world"
      dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

      result = HashToField.hash_to_field_fq2(message, 2, dst)

      assert length(result) == 2

      # Expected values - known correct results
      expected_0_c0 =
        1_717_481_801_022_890_320_930_535_539_684_145_078_363_416_826_664_358_709_416_530_433_123_807_602_906_499_236_696_635_892_172_619_530_864_997_493_102_515

      expected_0_c1 =
        1_687_859_148_152_866_701_283_814_945_283_565_263_051_278_093_529_837_438_184_411_703_051_446_645_270_323_793_737_296_154_376_182_401_617_592_571_421_593

      expected_1_c0 =
        3_901_330_900_121_520_942_627_673_142_142_849_187_437_938_066_868_251_070_015_462_714_176_845_045_056_507_979_389_850_416_409_317_326_499_549_712_481_614

      expected_1_c1 =
        2_175_242_699_958_839_247_752_417_837_689_044_546_354_080_322_814_340_310_702_597_681_413_282_346_860_771_490_707_418_120_088_238_564_234_612_358_749_630

      {actual_0_c0, actual_0_c1} = Enum.at(result, 0)
      actual_0_c0_int = :binary.decode_unsigned(actual_0_c0)
      actual_0_c1_int = :binary.decode_unsigned(actual_0_c1)

      {actual_1_c0, actual_1_c1} = Enum.at(result, 1)
      actual_1_c0_int = :binary.decode_unsigned(actual_1_c0)
      actual_1_c1_int = :binary.decode_unsigned(actual_1_c1)

      assert actual_0_c0_int == expected_0_c0
      assert actual_0_c1_int == expected_0_c1
      assert actual_1_c0_int == expected_1_c0
      assert actual_1_c1_int == expected_1_c1
    end

    test "produces correct result for test message" do
      message = "test"
      dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

      result = HashToField.hash_to_field_fq2(message, 1, dst)

      assert length(result) == 1

      # Expected values
      expected_c0 =
        3_535_058_899_757_572_561_417_273_661_736_812_582_163_214_854_283_886_200_950_085_587_678_672_134_917_564_981_097_203_652_298_787_502_167_092_805_260_296

      expected_c1 =
        3_638_938_364_795_184_900_703_046_711_520_950_876_176_833_374_715_311_617_602_086_474_128_845_885_923_931_415_454_445_068_484_712_548_218_201_064_420_152

      {actual_c0, actual_c1} = Enum.at(result, 0)
      actual_c0_int = :binary.decode_unsigned(actual_c0)
      actual_c1_int = :binary.decode_unsigned(actual_c1)

      assert actual_c0_int == expected_c0
      assert actual_c1_int == expected_c1
    end

    test "produces deterministic results" do
      message = "test message"
      dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

      result1 = HashToField.hash_to_field_fq2(message, 2, dst)
      result2 = HashToField.hash_to_field_fq2(message, 2, dst)

      assert result1 == result2, "hash_to_field_fq2 should be deterministic"
    end

    test "produces different results for different messages" do
      dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

      result1 = HashToField.hash_to_field_fq2("message1", 2, dst)
      result2 = HashToField.hash_to_field_fq2("message2", 2, dst)

      refute result1 == result2, "Different messages should produce different field elements"
    end

    test "respects count parameter" do
      message = "hello world"
      dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

      result_1 = HashToField.hash_to_field_fq2(message, 1, dst)
      result_2 = HashToField.hash_to_field_fq2(message, 2, dst)
      result_3 = HashToField.hash_to_field_fq2(message, 3, dst)

      assert length(result_1) == 1
      assert length(result_2) == 2
      assert length(result_3) == 3

      # First elements should be DIFFERENT when count changes (correct behavior per spec)
      assert Enum.at(result_1, 0) != Enum.at(result_2, 0)
      assert Enum.at(result_1, 0) != Enum.at(result_3, 0)
    end

    test "count parameter affects field element generation correctly" do
      message = "hello world"
      dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

      result_1 = HashToField.hash_to_field_fq2(message, 1, dst)
      result_2 = HashToField.hash_to_field_fq2(message, 2, dst)

      # The first elements should be DIFFERENT (this is correct behavior per spec)
      assert Enum.at(result_1, 0) != Enum.at(result_2, 0)
    end
  end

  describe "hash_to_g2" do
    test "produces valid points on the curve" do
      message = "hello world"

      result = HashToField.hash_to_g2(message)

      # For now, just verify it produces a valid G2 point
      # Once we fix the implementation, we can add exact value checks
      assert %{x: _, y: _, z: _} = result

      # The point should be on the curve (when implementation is correct)
      assert G2.is_on_curve?(result)
    end

    test "is deterministic" do
      message = "test message"

      result1 = HashToField.hash_to_g2(message)
      result2 = HashToField.hash_to_g2(message)

      # Should produce the same result every time
      assert G2.eq?(result1, result2)
    end

    test "produces different results for different messages" do
      result1 = HashToField.hash_to_g2("message1")
      result2 = HashToField.hash_to_g2("message2")

      # Should produce different results
      refute G2.eq?(result1, result2)
    end
  end
end
