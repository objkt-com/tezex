defmodule Tezex.Crypto.BLS.Fq12 do
  @moduledoc """
  The 12th-degree extension field Fq12 for BLS12-381.
  This is the target field for pairings: GT = Fq12.

  The field is constructed as Fq12 = Fq[x]/(x^12 + 2 - 2*x^6).
  """

  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.BLS.FqP
  alias Tezex.Crypto.Math

  @type t :: FqP.t()

  # BLS12-381 Fq12 modulus coefficients: x^12 + 2 - 2*x^6 = 0
  # So x^12 = 2*x^6 - 2
  # + implicit x^12 term
  @modulus_coeffs [2, 0, 0, 0, 0, 0, -2, 0, 0, 0, 0, 0]
  @zero Fq.zero()

  @doc """
  Creates an Fq12 element from a list of 12 Fq coefficients.
  """
  @spec new(list(Fq.t())) :: t()
  def new(coeffs) when is_list(coeffs) do
    FqP.new(coeffs, @modulus_coeffs)
  end

  @doc """
  Creates an Fq12 element from a list of coefficients and modulus coefficients.
  This is used for testing compatibility.
  """
  @spec new(list(Fq.t()), list(integer())) :: t()
  def new(coeffs, modulus_coeffs) when is_list(coeffs) and is_list(modulus_coeffs) do
    FqP.new(coeffs, modulus_coeffs)
  end

  @doc """
  Creates an Fq12 element from integers.
  """
  @spec from_integers(list(integer())) :: t()
  def from_integers(integers) when is_list(integers) do
    coeffs = Enum.map(integers, &Fq.from_integer/1)
    new(coeffs)
  end

  @doc """
  Returns the one element in Fq12.
  """
  @spec one() :: t()
  def one do
    FqP.one(@modulus_coeffs)
  end

  @doc """
  Returns the one element with custom modulus (for testing).
  """
  @spec one(list(integer())) :: t()
  def one(modulus_coeffs) do
    FqP.one(modulus_coeffs)
  end

  @doc """
  Adds two Fq12 elements.
  """
  @spec add(t(), t()) :: t()
  def add(a, b) do
    FqP.add(a, b)
  end

  @doc """
  Subtracts two Fq12 elements.
  """
  @spec sub(t(), t()) :: t()
  def sub(a, b) do
    FqP.sub(a, b)
  end

  @doc """
  Multiplies two Fq12 elements.
  """
  @spec mul(t(), t()) :: t()
  def mul(a, b) do
    FqP.mul(a, b)
  end

  @doc """
  Computes the modular inverse of an Fq12 element.
  Uses the FqP inverse implementation.
  """
  @spec inv(t()) :: t()
  def inv(a) do
    FqP.inv(a)
  end

  @doc """
  Divides two Fq12 elements (a / b = a * b^(-1)).
  """
  @spec field_div(t(), t()) :: t()
  def field_div(a, b) do
    mul(a, inv(b))
  end

  @doc """
  Raises an Fq12 element to a power.
  """
  @spec pow(t(), integer()) :: t()
  def pow(base, exponent) when exponent >= 0 do
    Math.binary_pow(base, exponent, one(), &mul/2)
  end

  @doc """
  Checks if an Fq12 element is zero.
  """
  @spec is_zero?(t()) :: boolean()
  def is_zero?(a) do
    FqP.is_zero?(a)
  end

  @doc """
  Checks if an Fq12 element is one.
  """
  @spec is_one?(t()) :: boolean()
  def is_one?(a) do
    FqP.eq?(a, one())
  end

  @doc """
  Checks if two Fq12 elements are equal.
  """
  @spec eq?(t(), t()) :: boolean()
  def eq?(a, b) do
    FqP.eq?(a, b)
  end

  # Frobenius endomorphism constants
  @f_1 3_699_099_184_852_670_630_486_504_326_366_823_957_760_732_022_002_356_992_020_042_909_103_225_195_948_437_585_701_677_765_097_109_891_745_284_740_289_733
  @f_2 151_655_185_184_498_381_465_642_749_684_540_099_398_075_398_968_325_446_656_007_613_510_403_227_271_200_139_370_504_932_015_952_886_146_304_766_135_027
  @f_3 793_479_390_729_215_512_621_379_701_633_421_447_060_886_740_281_060_493_010_456_487_427_281_649_075_476_305_620_758_731_620_351
  @f_4 4_002_409_555_221_667_392_624_310_435_006_688_643_935_503_118_305_586_438_271_171_395_842_971_157_480_381_377_015_405_980_053_539_358_417_135_540_939_436
  @f_5 1_028_732_146_235_106_349_975_324_479_215_795_277_384_839_936_929_757_896_155_643_118_032_610_843_298_655_225_875_571_310_552_543_014_690_878_354_869_257
  @f_6 4_002_409_555_221_667_392_624_310_435_006_688_643_935_503_118_305_586_438_271_171_395_842_971_157_480_381_377_015_405_980_053_539_358_417_135_540_939_437
  @f_7 1_754_153_922_101_215_937_019_363_459_062_510_355_973_529_075_922_864_898_999_271_009_044_415_232_054_910_173_010_132_757_073_180_257_089_147_177_468_460
  @f_8 3_125_332_594_171_059_424_908_108_096_204_648_978_570_118_281_977_575_435_832_422_631_601_824_034_463_382_777_937_621_250_592_425_535_493_320_683_825_557
  @f_9 4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_786
  @f_10 303_310_370_368_996_762_931_285_499_369_080_198_796_150_797_936_650_893_312_015_227_020_806_454_542_400_278_741_009_864_031_905_772_292_609_532_270_054
  @f_11 2_057_464_292_470_212_699_950_648_958_431_590_554_769_679_873_859_515_792_311_286_236_065_221_686_597_310_451_751_142_621_105_086_029_381_756_709_738_514
  @f_12 4_002_409_555_221_667_391_830_831_044_277_473_131_314_123_416_672_164_991_210_284_655_561_910_664_469_924_889_588_124_330_978_063_052_796_376_809_319_087
  @f_13 793_479_390_729_215_512_621_379_701_633_421_447_060_886_740_281_060_493_010_456_487_427_281_649_075_476_305_620_758_731_620_350
  @f_14 2_248_255_633_120_451_456_398_426_366_673_393_800_583_353_744_016_142_986_332_787_127_079_616_418_435_927_691_432_554_872_055_835_406_948_747_095_091_327

  # Frobenius endomorphism precomputed constants for BLS12-381
  # These represent x^i where x^p ≡ frobenius_constants[i] (mod field_modulus)
  # Allows efficient computation: φ(Σ a_i * x^i) = Σ a_i^p * frobenius_constants[i]
  @frobenius_constants [
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, @f_1, 0, 0, 0, 0, 0, @f_2, 0, 0, 0, 0],
    [0, 0, @f_3, 0, 0, 0, 0, 0, @f_4, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, @f_5, 0, 0],
    [0, 0, 0, 0, @f_6, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, @f_7, 0, 0, 0, 0, 0, @f_8],
    [2, 0, 0, 0, 0, 0, @f_9, 0, 0, 0, 0, 0],
    [0, @f_1, 0, 0, 0, 0, 0, @f_10, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, @f_4, 0, 0, 0],
    [0, 0, 0, @f_11, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, @f_12, 0, 0, 0, 0, 0, @f_13, 0],
    [0, 0, 0, 0, 0, @f_7, 0, 0, 0, 0, 0, @f_14]
  ]

  # Hard part exponent for BLS12-381 final exponentiation
  # This is (p^4 - p^2 + 1) / r, which is ~1268 bits instead of the naive ~4314 bits
  @hard_part_exponent 0xF686B3D807D01C0BD38C3195C899ED3CDE88EEB996CA394506632528D6A9A2F230063CF081517F68F7764C28B6F8AE5A72BCE8D63CB9F827ECA0BA621315B2076995003FC77A17988F8761BDC51DC2378B9039096D1B767F17FCBDE783765915C97F36C6F18212ED0B283ED237DB421D160AEB6A1E79983774940996754C8C71A2629B0DEA236905CE937335D5B68FA9912AAE208CCF1E516C3F438E3BA79

  @frobenius_base List.duplicate(@zero, 12)

  @doc """
  Computes the Frobenius endomorphism φ: Fq12 → Fq12 where φ(x) = x^p.
  This raises each coefficient to the power p and applies the precomputed basis transformation.
  """
  @spec frobenius(t()) :: t()
  def frobenius(%{coeffs: coeffs, modulus_coeffs: modulus_coeffs}) do
    # Apply Frobenius to each coefficient: a_i^p
    frobenius_coeffs = Enum.map(coeffs, &Fq.frobenius/1)

    # Apply the basis transformation using precomputed constants
    # φ(Σ a_i * x^i) = Σ a_i^p * frobenius_constants[i]
    coeffs =
      @frobenius_constants
      |> Enum.zip(frobenius_coeffs)
      |> Enum.reduce(@frobenius_base, fn {constant_coeffs, coeff}, acc ->
        constant_fq12 = from_integers(constant_coeffs)
        scaled = scalar_mul(constant_fq12, coeff)

        Enum.zip_with(acc, scaled.coeffs, &Fq.add/2)
      end)

    %{coeffs: coeffs, modulus_coeffs: modulus_coeffs}
  end

  @doc """
  Multiplies an Fq12 element by a scalar Fq element.
  """
  @spec scalar_mul(t(), Fq.t()) :: t()
  def scalar_mul(%{coeffs: coeffs, modulus_coeffs: modulus_coeffs}, scalar) do
    coeffs = Enum.map(coeffs, &Fq.mul(&1, scalar))
    %{coeffs: coeffs, modulus_coeffs: modulus_coeffs}
  end

  @doc """
  Optimized final exponentiation for BLS12-381.

  Instead of computing f^((p^12-1)/r) directly (~4314 bits), this computes:
  1. f^(p^2 + 1) using 2 Frobenius operations + 1 multiplication
  2. (f^(p^2 + 1))^(p^6 - 1) using 6 Frobenius operations + 1 inversion
  3. result^((p^4-p^2+1)/r) using optimized exponentiation (~1268 bits)

  This gives the same result as the naive approach but is much faster.
  Total: 8 Frobenius + 1 mul + 1 inv + 1 pow(1268 bits) vs 1 pow(4314 bits)
  """
  @spec optimized_final_exponentiation(t()) :: t()
  def optimized_final_exponentiation(f) do
    # Step 1: Compute f^(p^2 + 1)
    # p2 = frobenius(frobenius(f)) * f
    # f^p
    f_p = frobenius(f)
    # f^(p^2)
    f_p2 = frobenius(f_p)
    # f^(p^2 + 1)
    p2 = mul(f_p2, f)

    # Step 2: Compute (f^(p^2 + 1))^(p^6 - 1)
    # Apply 6 Frobenius operations to p2, then divide by p2
    temp = p2
    # p2^p
    temp = frobenius(temp)
    # p2^(p^2)
    temp = frobenius(temp)
    # p2^(p^3)
    temp = frobenius(temp)
    # p2^(p^4)
    temp = frobenius(temp)
    # p2^(p^5)
    temp = frobenius(temp)
    # p2^(p^6)
    temp = frobenius(temp)

    # p2^(p^6 - 1) = (f^(p^2+1))^(p^6-1)
    p3 = field_div(temp, p2)

    # Step 3: Compute p3^((p^4-p^2+1)/r)
    # This is the "hard part" but only 1268 bits instead of 4314
    pow(p3, @hard_part_exponent)
  end
end
