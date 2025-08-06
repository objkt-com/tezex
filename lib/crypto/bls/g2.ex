defmodule Tezex.Crypto.BLS.G2 do
  @moduledoc """
  G2 elliptic curve group for BLS12-381.

  This is the elliptic curve E'(Fq2): y² = x³ + 4(1 + u) over the quadratic extension Fq2.
  G2 is used for signatures in BLS signatures.

  Points are represented in Jacobian coordinates (X, Y, Z) where:
  - Affine coordinates: (X/Z², Y/Z³) over Fq2
  - Point at infinity: (1, 1, 0)
  """

  import Bitwise
  alias Tezex.Crypto.BLS.Constants
  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.BLS.Fq2
  alias Tezex.Crypto.BLS.Fr
  alias Tezex.Crypto.BLS.HashToField

  @type t :: %{x: Fq2.t(), y: Fq2.t(), z: Fq2.t()}

  @zero Fq2.zero()
  @one Fq2.one()

  # Curve coefficient B = 4(1 + u) in Fq2
  @curve_b_fq2 {Fq.from_integer(4), Fq.from_integer(4)}

  # SSWU constants for 3-isogeny curve mapping
  @iso_3_a Fq2.from_integers(0, 240)
  @iso_3_b Fq2.from_integers(1012, 1012)
  @iso_3_z Fq2.from_integers(-2, -1)

  # P_MINUS_9_DIV_16 for sqrt_division_FQ2
  @p_minus_9_div_16 1_001_205_140_483_106_588_246_484_290_269_935_788_605_945_006_208_159_541_241_399_033_561_623_546_780_709_821_462_541_004_956_387_089_373_434_649_096_260_670_658_193_992_783_731_681_621_012_512_651_314_777_238_193_313_314_641_988_297_376_025_498_093_520_728_838_658_813_979_860_931_248_214_124_593_092_835

  # ETAS for SSWU mapping
  @eta_1 Fq2.from_integers(
           1_015_919_005_498_129_635_886_032_702_454_337_503_112_659_152_043_614_931_979_881_174_103_627_376_789_972_962_005_013_361_970_813_319_613_593_700_736_144,
           1_244_231_661_155_348_484_223_428_017_511_856_347_821_538_750_986_231_559_855_759_541_903_146_219_579_071_812_422_210_818_684_355_842_447_591_283_616_181
         )
  @eta_2 Fq2.from_integers(
           -1_244_231_661_155_348_484_223_428_017_511_856_347_821_538_750_986_231_559_855_759_541_903_146_219_579_071_812_422_210_818_684_355_842_447_591_283_616_181,
           1_015_919_005_498_129_635_886_032_702_454_337_503_112_659_152_043_614_931_979_881_174_103_627_376_789_972_962_005_013_361_970_813_319_613_593_700_736_144
         )
  @eta_3 Fq2.from_integers(
           1_646_015_993_121_829_755_895_883_253_076_789_309_308_090_876_275_172_350_194_834_453_434_199_515_639_474_951_814_226_234_213_676_147_507_404_483_718_679,
           1_637_752_706_019_426_886_789_797_193_293_828_301_565_549_384_974_986_623_510_918_743_054_325_021_588_194_075_665_960_171_838_131_772_227_885_159_387_073
         )
  @eta_4 Fq2.from_integers(
           -1_637_752_706_019_426_886_789_797_193_293_828_301_565_549_384_974_986_623_510_918_743_054_325_021_588_194_075_665_960_171_838_131_772_227_885_159_387_073,
           1_646_015_993_121_829_755_895_883_253_076_789_309_308_090_876_275_172_350_194_834_453_434_199_515_639_474_951_814_226_234_213_676_147_507_404_483_718_679
         )
  @etas [@eta_1, @eta_2, @eta_3, @eta_4]

  # Positive eighth roots of unity for sqrt_division_FQ2
  @rv1 1_028_732_146_235_106_349_975_324_479_215_795_277_384_839_936_929_757_896_155_643_118_032_610_843_298_655_225_875_571_310_552_543_014_690_878_354_869_257
  @root_1 Fq2.from_integers(1, 0)
  @root_2 Fq2.from_integers(0, 1)
  @root_3 Fq2.from_integers(@rv1, @rv1)
  @root_4 Fq2.from_integers(@rv1, -@rv1)
  @eighth_roots [@root_1, @root_2, @root_3, @root_4]

  # Isogeny map coefficients for 3-isogeny mapping
  # X Numerator coefficients
  @iso_3_k_1_0_val 889_424_345_604_814_976_315_064_405_719_089_812_568_196_182_208_668_418_962_679_585_805_340_366_775_741_747_653_930_584_250_892_369_786_198_727_235_542
  @iso_3_k_1_0 Fq2.from_integers(@iso_3_k_1_0_val, @iso_3_k_1_0_val)
  @iso_3_k_1_1 Fq2.from_integers(
                 0,
                 2_668_273_036_814_444_928_945_193_217_157_269_437_704_588_546_626_005_256_888_038_757_416_021_100_327_225_242_961_791_752_752_677_109_358_596_181_706_522
               )
  @iso_3_k_1_2 Fq2.from_integers(
                 2_668_273_036_814_444_928_945_193_217_157_269_437_704_588_546_626_005_256_888_038_757_416_021_100_327_225_242_961_791_752_752_677_109_358_596_181_706_526,
                 1_334_136_518_407_222_464_472_596_608_578_634_718_852_294_273_313_002_628_444_019_378_708_010_550_163_612_621_480_895_876_376_338_554_679_298_090_853_261
               )
  @iso_3_k_1_3 Fq2.from_integers(
                 3_557_697_382_419_259_905_260_257_622_876_359_250_272_784_728_834_673_675_850_718_343_221_361_467_102_966_990_615_722_337_003_569_479_144_794_908_942_033,
                 0
               )
  @iso_3_x_numerator [@iso_3_k_1_0, @iso_3_k_1_1, @iso_3_k_1_2, @iso_3_k_1_3]

  # X Denominator coefficients
  @iso_3_k_2_0 Fq2.from_integers(
                 0,
                 4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_715
               )
  @iso_3_k_2_1 Fq2.from_integers(
                 12,
                 4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_775
               )
  @iso_3_k_2_2 @one
  @iso_3_k_2_3 @zero
  @iso_3_x_denominator [@iso_3_k_2_0, @iso_3_k_2_1, @iso_3_k_2_2, @iso_3_k_2_3]

  # Y Numerator coefficients
  @iso_3_k_3_0_val 3_261_222_600_550_988_246_488_569_487_636_662_646_083_386_001_431_784_202_863_158_481_286_248_011_511_053_074_731_078_808_919_938_689_216_061_999_863_558
  @iso_3_k_3_0 Fq2.from_integers(@iso_3_k_3_0_val, @iso_3_k_3_0_val)
  @iso_3_k_3_1 Fq2.from_integers(
                 0,
                 889_424_345_604_814_976_315_064_405_719_089_812_568_196_182_208_668_418_962_679_585_805_340_366_775_741_747_653_930_584_250_892_369_786_198_727_235_518
               )
  @iso_3_k_3_2 Fq2.from_integers(
                 2_668_273_036_814_444_928_945_193_217_157_269_437_704_588_546_626_005_256_888_038_757_416_021_100_327_225_242_961_791_752_752_677_109_358_596_181_706_524,
                 1_334_136_518_407_222_464_472_596_608_578_634_718_852_294_273_313_002_628_444_019_378_708_010_550_163_612_621_480_895_876_376_338_554_679_298_090_853_263
               )
  @iso_3_k_3_3 Fq2.from_integers(
                 2_816_510_427_748_580_758_331_037_284_777_117_739_799_287_910_327_449_993_381_818_688_383_577_828_123_182_200_904_113_516_794_492_504_322_962_636_245_776,
                 0
               )
  @iso_3_y_numerator [@iso_3_k_3_0, @iso_3_k_3_1, @iso_3_k_3_2, @iso_3_k_3_3]

  # Y Denominator coefficients
  @iso_3_k_4_0_val 4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_355
  @iso_3_k_4_0 Fq2.from_integers(@iso_3_k_4_0_val, @iso_3_k_4_0_val)
  @iso_3_k_4_1 Fq2.from_integers(
                 0,
                 4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_571
               )
  @iso_3_k_4_2 Fq2.from_integers(
                 18,
                 4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_769
               )
  @iso_3_k_4_3 @one
  @iso_3_y_denominator [@iso_3_k_4_0, @iso_3_k_4_1, @iso_3_k_4_2, @iso_3_k_4_3]

  @iso_3_map_coefficients [
    @iso_3_x_numerator,
    @iso_3_x_denominator,
    @iso_3_y_numerator,
    @iso_3_y_denominator
  ]

  # Efficient cofactor for G2 (H_EFF_G2)
  @h_eff_g2 209_869_847_837_335_686_905_080_341_498_658_477_663_839_067_235_703_451_875_306_851_526_599_783_796_572_738_804_459_333_109_033_834_234_622_528_588_876_978_987_822_447_936_461_846_631_641_690_358_257_586_228_683_615_991_308_971_558_879_306_463_436_166_481

  # Generator point coordinates in affine form (from ZCash BLS12-381 spec)
  # x.c0 = 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160
  @generator_x_c0_int 352_701_069_587_466_618_187_139_116_011_060_144_890_029_952_792_775_240_219_908_644_239_793_785_735_715_026_873_347_600_343_865_175_952_761_926_303_160
  # x.c1 = 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758
  @generator_x_c1_int 3_059_144_344_244_213_709_971_259_814_753_781_636_986_470_325_476_647_558_659_373_206_291_635_324_768_958_432_433_509_563_104_347_017_837_885_763_365_758
  # y.c0 = 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905
  @generator_y_c0_int 1_985_150_602_287_291_935_568_054_521_177_171_638_300_868_978_215_655_730_859_378_665_066_344_726_373_823_718_423_869_104_263_333_984_641_494_340_347_905
  # y.c1 = 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582
  @generator_y_c1_int 927_553_665_492_332_455_747_201_965_776_037_880_757_740_193_453_592_970_025_027_978_793_976_877_002_675_564_980_949_289_727_957_565_575_433_344_219_582

  @generator_x {Fq.from_integer(@generator_x_c0_int), Fq.from_integer(@generator_x_c1_int)}
  @generator_y {Fq.from_integer(@generator_y_c0_int), Fq.from_integer(@generator_y_c1_int)}

  @doc """
  Creates a G2 point from Jacobian coordinates.
  """
  @spec new(Fq2.t(), Fq2.t(), Fq2.t()) :: t()
  def new(x, y, z) do
    %{x: x, y: y, z: z}
  end

  @doc """
  Returns the point at infinity (identity element).
  """
  @spec zero() :: t()
  def zero do
    new(@one, @one, @zero)
  end

  @doc """
  Returns the generator point for G2.
  """
  @spec generator() :: t()
  def generator do
    x = @generator_x
    y = @generator_y
    z = @one

    new(x, y, z)
  end

  @doc """
  Checks if a point is the point at infinity.
  """
  @spec is_zero?(t()) :: boolean()
  def is_zero?(%{z: z}) do
    Fq2.is_zero?(z)
  end

  @doc """
  Alias for is_zero?/1 for compatibility.
  """
  @spec is_infinity?(t()) :: boolean()
  def is_infinity?(point), do: is_zero?(point)

  @doc """
  Checks if a point is on the curve.
  """
  @spec is_on_curve?(t()) :: boolean()
  def is_on_curve?(point) do
    if is_zero?(point) do
      true
    else
      %{x: x, y: y, z: z} = point

      # Check curve equation in Jacobian coordinates:
      # y^2 * z - x^3 == b * z^3
      y_squared = Fq2.square(y)
      y_squared_z = Fq2.mul(y_squared, z)

      x_cubed = Fq2.mul(Fq2.square(x), x)

      z_cubed = Fq2.mul(Fq2.square(z), z)
      b_z_cubed = Fq2.mul(@curve_b_fq2, z_cubed)

      # Check: y^2 * z - x^3 == b * z^3
      # we rearranged: y^2 * z == x^3 + b * z^3

      Fq2.eq?(y_squared_z, Fq2.add(x_cubed, b_z_cubed))
    end
  end

  @doc """
  Doubles a G2 point.
  """
  @spec double(t()) :: t()
  def double(point) do
    if is_zero?(point) do
      zero()
    else
      %{x: x, y: y, z: z} = point

      # Point doubling algorithm:
      # W = 3 * x * x
      w = Fq2.mul_scalar(Fq2.square(x), 3)

      # S = y * z
      s = Fq2.mul(y, z)

      # B = x * y * S
      b = Fq2.mul(Fq2.mul(x, y), s)

      # H = W * W - 8 * B
      eight_b = Fq2.mul_scalar(b, 8)
      h = Fq2.sub(Fq2.square(w), eight_b)

      # S_squared = S * S
      s_squared = Fq2.square(s)

      # newx = 2 * H * S
      newx = Fq2.mul(Fq2.mul_scalar(h, 2), s)

      # newy = W * (4 * B - H) - 8 * y * y * S_squared
      four_b = Fq2.mul_scalar(b, 4)
      four_b_minus_h = Fq2.sub(four_b, h)
      y_squared = Fq2.square(y)
      eight_y_squared_s_squared = Fq2.mul_scalar(Fq2.mul(y_squared, s_squared), 8)
      newy = Fq2.sub(Fq2.mul(w, four_b_minus_h), eight_y_squared_s_squared)

      # newz = 8 * S * S_squared
      newz = Fq2.mul_scalar(Fq2.mul(s, s_squared), 8)

      new(newx, newy, newz)
    end
  end

  @doc """
  Adds two G2 points.
  """
  @spec add(t(), t()) :: t()
  def add(p1, p2) do
    cond do
      is_zero?(p1) -> p2
      is_zero?(p2) -> p1
      eq?(p1, p2) -> double(p1)
      true -> add_different(p1, p2)
    end
  end

  # Helper for adding two different points
  # Optimized addition algorithm
  defp add_different(p1, p2) do
    %{x: x1, y: y1, z: z1} = p1
    %{x: x2, y: y2, z: z2} = p2

    # Addition algorithm:
    # U1 = y2 * z1
    u1 = Fq2.mul(y2, z1)

    # U2 = y1 * z2
    u2 = Fq2.mul(y1, z2)

    # V1 = x2 * z1
    v1 = Fq2.mul(x2, z1)

    # V2 = x1 * z2
    v2 = Fq2.mul(x1, z2)

    # Check if points are the same or inverses
    if Fq2.eq?(v1, v2) do
      if Fq2.eq?(u1, u2) do
        # Same point
        double(p1)
      else
        # Inverse points (return point at infinity)
        zero()
      end
    else
      # U = U1 - U2
      u = Fq2.sub(u1, u2)

      # V = V1 - V2
      v = Fq2.sub(v1, v2)

      # V_squared = V * V
      v_squared = Fq2.square(v)

      # V_squared_times_V2 = V_squared * V2
      v_squared_times_v2 = Fq2.mul(v_squared, v2)

      # V_cubed = V * V_squared
      v_cubed = Fq2.mul(v, v_squared)

      # W = z1 * z2
      w = Fq2.mul(z1, z2)

      # A = U * U * W - V_cubed - 2 * V_squared_times_V2
      u_squared = Fq2.square(u)
      u_squared_w = Fq2.mul(u_squared, w)
      two_v_squared_times_v2 = Fq2.add(v_squared_times_v2, v_squared_times_v2)
      a = Fq2.sub(Fq2.sub(u_squared_w, v_cubed), two_v_squared_times_v2)

      # newx = V * A
      newx = Fq2.mul(v, a)

      # newy = U * (V_squared_times_V2 - A) - V_cubed * U2
      newy =
        Fq2.sub(
          Fq2.mul(u, Fq2.sub(v_squared_times_v2, a)),
          Fq2.mul(v_cubed, u2)
        )

      # newz = V_cubed * W
      newz = Fq2.mul(v_cubed, w)

      new(newx, newy, newz)
    end
  end

  @doc """
  Negates a G2 point.
  """
  @spec negate(t()) :: t()
  def negate(point) do
    if is_zero?(point) do
      zero()
    else
      new(point.x, Fq2.neg(point.y), point.z)
    end
  end

  @doc """
  Hash-to-curve for G2 - maps a message to a point on G2.
  Implements hash-to-curve following IRTF standards.
  """
  @spec hash_to_curve(binary(), binary()) :: t()
  def hash_to_curve(message, ciphersuite) when is_binary(message) and is_binary(ciphersuite) do
    # Proper hash-to-curve implementation following IRTF standard
    HashToField.hash_to_g2(message, ciphersuite)
  end

  @doc """
  Multiplies a G2 point by a scalar using double-and-add algorithm.
  """
  @spec mul(t(), Fr.t()) :: t()
  def mul(point, scalar) when byte_size(scalar) == 32 do
    if is_zero?(point) do
      zero()
    else
      # Convert scalar to integer for bit operations
      scalar_int = Fr.to_integer(scalar)
      scalar_multiplication(point, scalar_int)
    end
  end

  @doc """
  Multiplies a G2 point by a large integer (for cofactor clearing).
  """
  @spec mul_integer(t(), non_neg_integer()) :: t()
  def mul_integer(point, scalar_int) when is_integer(scalar_int) do
    if is_zero?(point) do
      zero()
    else
      scalar_multiplication(point, scalar_int)
    end
  end

  # Scalar multiplication algorithm
  defp scalar_multiplication(_point, 0) do
    zero()
  end

  defp scalar_multiplication(point, 1) do
    point
  end

  defp scalar_multiplication(point, n) when rem(n, 2) == 0 do
    scalar_multiplication(double(point), div(n, 2))
  end

  defp scalar_multiplication(point, n) do
    doubled_result = scalar_multiplication(double(point), div(n, 2))
    add(doubled_result, point)
  end

  @doc """
  Checks if two G2 points are equal.
  """
  @spec eq?(t(), t()) :: boolean()
  def eq?(p1, p2) do
    cond do
      is_zero?(p1) and is_zero?(p2) -> true
      is_zero?(p1) or is_zero?(p2) -> false
      true -> eq_different?(p1, p2)
    end
  end

  # Check equality for non-zero points in projective coordinates
  # Check: x1 * z2 == x2 * z1 and y1 * z2 == y2 * z1
  defp eq_different?(p1, p2) do
    %{x: x1, y: y1, z: z1} = p1
    %{x: x2, y: y2, z: z2} = p2

    # Check X coordinate equality: X1*Z2 == X2*Z1
    x1_cross = Fq2.mul(x1, z2)
    x2_cross = Fq2.mul(x2, z1)

    if Fq2.eq?(x1_cross, x2_cross) do
      # Check Y coordinate equality: Y1*Z2 == Y2*Z1
      y1_cross = Fq2.mul(y1, z2)
      y2_cross = Fq2.mul(y2, z1)
      Fq2.eq?(y1_cross, y2_cross)
    else
      false
    end
  end

  @doc """
  Converts a G2 point to affine coordinates.
  """
  @spec to_affine(t()) :: {:ok, {Fq2.t(), Fq2.t()}} | {:error, :point_at_infinity}
  def to_affine(point) do
    if is_zero?(point) do
      {:error, :point_at_infinity}
    else
      %{x: x, y: y, z: z} = point

      case Fq2.inv(z) do
        {:ok, z_inv} ->
          # Use projective coordinates: (x/z, y/z) instead of Jacobian (x/z^2, y/z^3)
          affine_x = Fq2.mul(x, z_inv)
          affine_y = Fq2.mul(y, z_inv)

          {:ok, {affine_x, affine_y}}

        {:error, _} ->
          {:error, :point_at_infinity}
      end
    end
  end

  @doc """
  Creates a G2 point from affine coordinates.
  """
  @spec from_affine(Fq2.t(), Fq2.t()) :: t()
  def from_affine(x, y) do
    new(x, y, @one)
  end

  # Bit shift constants for compressed encoding
  @pow_2_381 1 <<< 381
  @pow_2_382 1 <<< 382
  @pow_2_383 1 <<< 383
  # Point at infinity - compression and infinity flags in x_c1 first
  # x_c1 has 0xC0 as first byte, then x_c0 is all zeros
  @infinity <<0xC0, 0::376, 0::384>>

  @doc """
  Serializes a G2 point to compressed format (96 bytes).
  """
  @spec to_compressed_bytes(t()) :: binary()
  def to_compressed_bytes(point) do
    if is_zero?(point) do
      @infinity
    else
      case to_affine(point) do
        {:ok, {x, y}} ->
          # x is an Fq2 element {x_c0, x_c1}
          {x_c0, x_c1} = x

          # Serialize x coordinates (48 bytes each)
          x_c0_bytes = Fq.to_bytes(x_c0)
          x_c1_bytes = Fq.to_bytes(x_c1)

          # Determine y coordinate parity for compression
          # Parity calculation: (y_im * 2)
          {y_c0, y_c1} = y
          y_c0_int = Fq.to_integer(y_c0)
          y_c1_int = Fq.to_integer(y_c1)

          field_modulus = Constants.field_modulus()

          y_parity =
            if y_c1_int > 0 do
              div(y_c1_int * 2, field_modulus)
            else
              div(y_c0_int * 2, field_modulus)
            end

          # Set compression flag and parity bit on x_c1 (imaginary part)
          <<first_byte, rest::binary>> = x_c1_bytes
          # Clear the top 3 bits and set compression flag (0x80) and y parity (0x20 if odd)
          compressed_first_byte = (first_byte &&& 0x1F) ||| 0x80 ||| y_parity <<< 5

          # Store in standard format: x_c1 (imaginary) first, then x_c0 (real)
          <<compressed_first_byte>> <> rest <> x_c0_bytes

        {:error, _} ->
          @infinity
      end
    end
  end

  @doc """
  Deserializes a G2 point from compressed format (96 bytes).
  """
  @spec from_compressed_bytes(binary()) :: {:ok, t()} | {:error, :invalid_point}
  def from_compressed_bytes(bytes) when byte_size(bytes) == 96 do
    # Parse as two 48-byte big-endian integers (z1, z2)
    <<z1_bytes::binary-size(48), z2_bytes::binary-size(48)>> = bytes

    z1 = :binary.decode_unsigned(z1_bytes, :big)
    z2 = :binary.decode_unsigned(z2_bytes, :big)

    # Extract flags from z1 (top 3 bits)
    # Compression flag (should be 1)
    c_flag1 = z1 >>> 383 &&& 1
    # Infinity flag
    b_flag1 = z1 >>> 382 &&& 1
    # Y parity flag
    a_flag1 = z1 >>> 381 &&& 1

    # Check compression flag
    if c_flag1 != 1 do
      {:error, :invalid_point}
    else
      # Point at infinity check
      if b_flag1 == 1 do
        # Point at infinity should have a_flag1 == 0 and specific pattern
        if a_flag1 == 0 do
          # Check for proper infinity encoding
          # 0xC0 prefix
          expected_z1 = @pow_2_383 ||| @pow_2_382

          if z1 == expected_z1 and z2 == 0 do
            {:ok, zero()}
          else
            {:error, :invalid_point}
          end
        else
          {:error, :invalid_point}
        end
      else
        # Extract x coordinate (clear top 3 bits from z1)
        # x1 is imaginary part
        x1 = z1 &&& @pow_2_381 - 1
        # x2 is real part
        x2 = z2

        # Check field bounds
        field_modulus = Constants.field_modulus()

        if x1 >= field_modulus or x2 >= field_modulus do
          {:error, :invalid_point}
        else
          # Create Fq elements and build x coordinate
          x_real = Fq.from_integer(x2)
          x_imag = Fq.from_integer(x1)
          # x = x2 + x1*u (real + imaginary*u)
          x = {x_real, x_imag}

          # Compute y coordinate from curve equation: y² = x³ + 4(1 + u)
          x_cubed = Fq2.mul(Fq2.square(x), x)
          y_squared = Fq2.add(x_cubed, @curve_b_fq2)

          {is_valid, y} = sqrt_division_fq2(y_squared, @one)

          if is_valid do
            # Choose correct y based on parity
            {y_real, y_imag} = y
            y_real_int = Fq.to_integer(y_real)
            y_imag_int = Fq.to_integer(y_imag)

            computed_parity =
              if y_imag_int > 0 do
                div(y_imag_int * 2, field_modulus)
              else
                div(y_real_int * 2, field_modulus)
              end

            final_y =
              if computed_parity == a_flag1 do
                y
              else
                Fq2.neg(y)
              end

            point = from_affine(x, final_y)

            # Verify the point is on the curve
            if is_on_curve?(point) do
              {:ok, point}
            else
              {:error, :invalid_point}
            end
          else
            {:error, :invalid_point}
          end
        end
      end
    end
  end

  def from_compressed_bytes(_), do: {:error, :invalid_point}

  @doc """
  Optimized SSWU Map for G2.
  Maps an FQ2 element to a point on the 3-isogenous curve.
  """
  @spec sswu_map(Fq2.t()) :: {Fq2.t(), Fq2.t(), Fq2.t()}
  def sswu_map(t) do
    # t^2
    t2 = Fq2.square(t)

    # ISO_3_Z * t^2
    iso_3_z_t2 = Fq2.mul(@iso_3_z, t2)

    # Z * t^2 + Z^2 * t^4
    temp = Fq2.add(iso_3_z_t2, Fq2.square(iso_3_z_t2))

    # -a(Z * t^2 + Z^2 * t^4)
    denominator = Fq2.neg(Fq2.mul(@iso_3_a, temp))

    # Z * t^2 + Z^2 * t^4 + 1
    temp = Fq2.add(temp, @one)

    # b(Z * t^2 + Z^2 * t^4 + 1)
    numerator = Fq2.mul(@iso_3_b, temp)

    # Exceptional case: if denominator is zero
    denominator =
      if Fq2.is_zero?(denominator) do
        Fq2.mul(@iso_3_z, @iso_3_a)
      else
        denominator
      end

    # v = D^3
    v = Fq2.pow(denominator, 3)

    # u = N^3 + a * N * D^2 + b * D^3
    numerator_cubed = Fq2.pow(numerator, 3)
    denominator_squared = Fq2.square(denominator)
    term1 = Fq2.mul(@iso_3_a, Fq2.mul(numerator, denominator_squared))
    term2 = Fq2.mul(@iso_3_b, v)
    u = Fq2.add(Fq2.add(numerator_cubed, term1), term2)

    # Attempt y = sqrt(u / v)
    {success, sqrt_candidate} = sqrt_division_fq2(u, v)
    y = sqrt_candidate

    # Handle case where (u / v) is not square
    # sqrt_candidate(x1) = sqrt_candidate(x0) * t^3
    sqrt_candidate = Fq2.mul(sqrt_candidate, Fq2.pow(t, 3))

    # u(x1) = Z^3 * t^6 * u(x0)
    u = Fq2.mul(Fq2.pow(iso_3_z_t2, 3), u)

    success_2 = check_eta_candidates(sqrt_candidate, v, u)

    y =
      if success_2 do
        find_eta_solution(sqrt_candidate, v, u)
      else
        y
      end

    if not success and not success_2 do
      raise "Hash to Curve - Optimized SWU failure"
    end

    numerator =
      if not success do
        Fq2.mul(numerator, iso_3_z_t2)
      else
        numerator
      end

    # Sign correction
    y =
      if Fq2.sgn0(t) != Fq2.sgn0(y) do
        Fq2.neg(y)
      else
        y
      end

    y = Fq2.mul(y, denominator)

    {numerator, y, denominator}
  end

  # Square root division for FQ2
  defp sqrt_division_fq2(u, v) do
    temp1 = Fq2.mul(u, Fq2.pow(v, 7))
    temp2 = Fq2.mul(temp1, Fq2.pow(v, 8))

    # gamma = uv^7 * (uv^15)^((p^2 - 9) / 16)
    gamma = Fq2.mul(Fq2.pow(temp2, @p_minus_9_div_16), temp1)

    # Check for valid root using eighth roots of unity
    {is_valid_root, result} = check_eighth_roots(gamma, v, u)

    {is_valid_root, result}
  end

  defp check_eighth_roots(gamma, v, u) do
    Enum.reduce_while(@eighth_roots, {false, gamma}, fn root, {is_valid, result} ->
      if is_valid do
        {:halt, {is_valid, result}}
      else
        sqrt_candidate = Fq2.mul(root, gamma)
        temp = Fq2.sub(Fq2.mul(Fq2.square(sqrt_candidate), v), u)

        if Fq2.is_zero?(temp) do
          {:halt, {true, sqrt_candidate}}
        else
          {:cont, {false, gamma}}
        end
      end
    end)
  end

  defp check_eta_candidates(sqrt_candidate, v, u) do
    Enum.any?(@etas, fn eta ->
      eta_sqrt_candidate = Fq2.mul(eta, sqrt_candidate)
      temp = Fq2.sub(Fq2.mul(Fq2.square(eta_sqrt_candidate), v), u)
      Fq2.is_zero?(temp)
    end)
  end

  defp find_eta_solution(sqrt_candidate, v, u) do
    Enum.reduce_while(@etas, nil, fn eta, _acc ->
      eta_sqrt_candidate = Fq2.mul(eta, sqrt_candidate)
      temp = Fq2.sub(Fq2.mul(Fq2.square(eta_sqrt_candidate), v), u)

      if Fq2.is_zero?(temp) do
        {:halt, eta_sqrt_candidate}
      else
        {:cont, nil}
      end
    end)
  end

  @doc """
  Isogeny mapping from 3-isogenous curve to G2.
  3-isogeny mapping from E'(Fq2) to E(Fq2).
  """
  @spec iso_map_g2(Fq2.t(), Fq2.t(), Fq2.t()) :: {Fq2.t(), Fq2.t(), Fq2.t()}
  def iso_map_g2(x, y, z) do
    # x-numerator, x-denominator, y-numerator, y-denominator
    mapped_values = [@zero, @zero, @zero, @zero]
    z_powers = [z, Fq2.square(z), Fq2.pow(z, 3)]

    # Horner Polynomial Evaluation for each coefficient set
    mapped_values =
      Enum.with_index(@iso_3_map_coefficients)
      |> Enum.reduce(mapped_values, fn {k_i, i}, acc ->
        # Start with the highest degree coefficient (last element)
        result = List.last(k_i)

        # Evaluate polynomial using Horner's method
        result =
          k_i
          |> Enum.reverse()
          # Skip the last element we already used
          |> Enum.drop(1)
          |> Enum.with_index()
          |> Enum.reduce(result, fn {k_i_j, j}, poly_acc ->
            z_power = Enum.at(z_powers, j)
            term = Fq2.mul(z_power, k_i_j)
            Fq2.add(Fq2.mul(poly_acc, x), term)
          end)

        List.replace_at(acc, i, result)
      end)

    [x_num, x_den, y_num, y_den] = mapped_values

    # y-numerator * y and y-denominator * z
    y_num = Fq2.mul(y_num, y)
    y_den = Fq2.mul(y_den, z)

    # Final coordinates
    # x-denominator * y-denominator
    z_g2 = Fq2.mul(x_den, y_den)
    # x-numerator * y-denominator
    x_g2 = Fq2.mul(x_num, y_den)
    # x-denominator * y-numerator
    y_g2 = Fq2.mul(x_den, y_num)

    {x_g2, y_g2, z_g2}
  end

  @doc """
  Clear the cofactor of a G2 point to map it to the prime-order subgroup.
  Uses the efficient cofactor H_EFF_G2.
  """
  @spec clear_cofactor(t()) :: t()
  def clear_cofactor(point) do
    mul_integer(point, @h_eff_g2)
  end
end
