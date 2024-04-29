defmodule Tezex.MichelineTest do
  use ExUnit.Case, async: true

  alias Tezex.Forge
  alias Tezex.Micheline

  doctest Tezex.Micheline

  describe "pack" do
    result = Micheline.pack(9, :int)
    assert result == "050009"

    result = Micheline.pack(9, :nat)
    assert result == "050009"

    result = Micheline.pack(-9, :int)
    assert result == "050049"

    result = Micheline.pack(-6407, :int)
    assert result == "0500c764"

    result = Micheline.pack(98_978_654, :int)
    assert result == "05009eadb25e"

    result = Micheline.pack(-78_181_343_541, :int)
    assert result == "0500f584c5bfc604"

    result = Micheline.pack("tz1eEnQhbwf6trb8Q8mPb2RaPkNk2rN7BKi8", :address)
    assert result == "050a000000160000cc04e65d3e38e4e8059041f27a649c76630f95e2"

    result = Micheline.pack("tz1eEnQhbwf6trb8Q8mPb2RaPkNk2rN7BKi8", :key_hash)
    assert result == "050a000000160000cc04e65d3e38e4e8059041f27a649c76630f95e2"

    result = Micheline.pack("Tezos Tacos Nachos", :string)
    assert result == "05010000001254657a6f73205461636f73204e6163686f73"

    result = Micheline.pack(:binary.decode_hex("0a0a0a"), :bytes)
    assert result == "050a000000030a0a0a"

    result = Micheline.pack(%{"prim" => "Pair", "args" => [%{"int" => "1"}, %{"int" => "12"}]})
    assert result == "0507070001000c"

    value = %{
      "prim" => "Pair",
      "args" => [
        %{"int" => "42"},
        %{
          "prim" => "Left",
          "args" => [
            %{
              "prim" => "Left",
              "args" => [
                %{"prim" => "Pair", "args" => [%{"int" => "1585470660"}, %{"int" => "900100"}]}
              ]
            }
          ]
        }
      ]
    }

    assert Micheline.pack(value) == "050707002a0505050507070084f382e80b0084f06d"
  end

  describe "unpack" do
    test "micheline" do
      # https://better-call.dev/ghostnet/opg/opBDW8y9HYyhPysKT8YYzgZC8rKFnHUwnkxAXYQaajgiotdMf2v/contents
      expected = [
        %{
          "args" => [
            %{"bytes" => "0000078694ecd15392219b7e47814ecfa11f90192642"},
            %{"int" => "5000"}
          ],
          "prim" => "Elt"
        },
        %{
          "args" => [
            %{"bytes" => "00007fc95c97fd368cd9055610ee79e64ff9e0b5285c"},
            %{"int" => "5000"}
          ],
          "prim" => "Elt"
        }
      ]

      assert expected ==
               Micheline.unpack(
                 "05020000004007040a000000160000078694ecd15392219b7e47814ecfa11f9019264200884e07040a0000001600007fc95c97fd368cd9055610ee79e64ff9e0b5285c00884e"
               )

      assert ["tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z", "tz1XHhjLXQuG9rf9n7o1VbgegMkiggy1oktu"] ==
               Enum.map(expected, fn %{"args" => [%{"bytes" => bytes} | _]} ->
                 bytes
                 |> :binary.decode_hex()
                 |> Forge.unforge_address()
               end)
    end

    test "various values" do
      result = Micheline.unpack("050009", :int)
      assert result == 9

      result = Micheline.unpack("050009", :nat)
      assert result == 9

      result = Micheline.unpack("050049", :int)
      assert result == -9

      result = Micheline.unpack("0500c764", :int)
      assert result == -6407

      result = Micheline.unpack("05009eadb25e", :int)
      assert result == 98_978_654

      result = Micheline.unpack("0500f584c5bfc604", :int)
      assert result == -78_181_343_541

      result =
        Micheline.unpack("050a0000001500cc04e65d3e38e4e8059041f27a649c76630f95e2", :key_hash)

      assert result == "tz1eEnQhbwf6trb8Q8mPb2RaPkNk2rN7BKi8"

      result =
        Micheline.unpack("050a0000001601e67bac124dff100a57644de0cf26d341ebf9492600", :address)

      assert result == "KT1VbT8n6YbrzPSjdAscKfJGDDNafB5yHn1H"

      result = Micheline.unpack("05010000001254657a6f73205461636f73204e6163686f73", :string)
      assert result == "Tezos Tacos Nachos"

      result = Micheline.unpack("050a000000030a0a0a", :bytes)
      assert result == "0a0a0a"

      result = Micheline.unpack("0507070001000c")
      assert result == %{"prim" => "Pair", "args" => [%{"int" => "1"}, %{"int" => "12"}]}
    end
  end
end
