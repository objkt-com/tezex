defmodule Tezex.Crypto.ECDSA.Test do
  use ExUnit.Case

  alias Tezex.Crypto.ECDSA
  alias EllipticCurve.Point
  alias EllipticCurve.Curve.KnownCurves

  test "decode_point" do
    curve = KnownCurves.getCurveByName(:prime256v1)

    pk =
      <<2, 184, 135, 160, 166, 159, 170, 245, 126, 53, 185, 225, 207, 159, 136, 196, 23, 208, 233,
        145, 105, 146, 245, 7, 83, 30, 104, 171, 220, 231, 147, 247, 199>>

    assert ECDSA.decode_point(pk, curve) == %Point{
             x:
               83_465_197_264_647_713_393_437_352_350_638_497_449_827_832_007_707_948_520_652_053_765_146_658_731_975,
             y:
               88_143_159_976_858_809_297_287_334_524_779_257_190_097_940_930_305_912_306_738_605_636_423_540_342_692,
             z: 0
           }
  end
end
