defmodule Tezex.Crypto.BLS.Constants do
  @moduledoc """
  BLS12-381 curve constants for pairing computation.
  Standard BLS12-381 curve constants.
  """

  # BLS12-381 field modulus
  @field_modulus 4_002_409_555_221_667_393_417_789_825_735_904_156_556_882_819_939_007_885_332_058_136_124_031_650_490_837_864_442_687_629_129_015_664_037_894_272_559_787

  # Curve order (number of points on the curve)
  @curve_order 52_435_875_175_126_190_479_447_740_508_185_965_837_690_552_500_527_637_822_603_658_699_938_581_184_513

  # Pseudo-binary encoding of the ATE loop count for the BLS12-381 Miller loop.
  # Source string is LSB-first (64 bits); the Miller loop iterates bits 62..0,
  # so we precompute that iteration order once at compile time.
  @miller_loop_bits "0000000000000000100000000000000000000000000000001000000001001011"
                    |> String.graphemes()
                    |> Enum.map(&String.to_integer/1)
                    |> Enum.slice(0..62)
                    |> Enum.reverse()

  63 = length(@miller_loop_bits)

  def field_modulus, do: @field_modulus
  def curve_order, do: @curve_order
  def miller_loop_bits, do: @miller_loop_bits
end
