defmodule Tezex.ForgeTest do
  use ExUnit.Case, async: true

  alias Tezex.Forge
  alias Tezex.ForgeOperation

  describe "specific forge/unforge" do
    test "address" do
      addr = "tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z"

      assert "0000078694ecd15392219b7e47814ecfa11f90192642" ==
               Forge.forge_address(addr, :hex)

      assert Forge.unforge_address(Forge.forge_address(addr)) == addr
    end

    test "public_key" do
      sig = "edpktsPhZ8weLEXqf4Fo5FS9Qx8ZuX4QpEBEwe63L747G8iDjTAF6w"

      assert "001de67a53b0d3ab18dd6c415da17c9f83015489cde2c7165a3ada081a6049b78f" ==
               Forge.forge_public_key(sig, :hex)

      assert Forge.unforge_public_key(Forge.forge_public_key(sig)) == sig
    end

    test "forge_base58" do
      v = "BKpLvH3E3bUa5Z2nb3RkH2p6EKLfymvxUAEgtRJnu4m9UX1TWUb"

      assert Forge.forge_base58(v, :hex) ==
               "0dc397b7865779d87bd47d406e8b4eee84498f22ab01dff124433c7f057af5ae"
    end

    test "unforge_signature" do
      input =
        "49d47dba27bd76208b092f3e500f64818920c817491b8b9094f28c2c2b9c6721b257b8878ce47182122b8ea84aeacd84a8aa28cb1f1fe48a26355a7bca4b8306"

      output =
        "sigXeXB5JD5TaLb3xgTPKjgf9W45judiCmNP9UBdZBdmtHSGBxL1M8ZSUb6LpjGP2MdfUBTB4WHs5APnvyRV1LooU6QHJuDe"

      assert Forge.unforge_signature(input, :hex) == output
    end

    test "un/forge int" do
      xs = [
        {{-1, 1}, <<65>>},
        {{0, 1}, <<0>>},
        {{1, 1}, <<1>>},
        {{63, 1}, <<63>>},
        {{64, 2}, <<128, 1>>},
        {{12_349_129_381_238, 7}, <<182, 213, 194, 151, 232, 206, 5>>},
        {{-12_349_129_381_238, 7}, <<246, 213, 194, 151, 232, 206, 5>>}
      ]

      Enum.each(xs, fn {{decoded, len}, encoded} ->
        assert Forge.forge_int(decoded) == encoded
        assert Forge.unforge_int(encoded) == {decoded, len}
      end)

      assert Forge.unforge_int(
               "000521000307430359030a0743035d0a00000015002523250b271e153be6c2668954114be101d04d3d05700005054200030342034d",
               :hex
             ) == {0, 1}
    end

    test "branch" do
      assert "560a037fdd573fcb59a49b5835658fab813b57b3a25e96710ec97aad0614c34f" ==
               Forge.forge_base58("BLNB68pLiAgXiJHXNUK7CDKRnCx1TqzaNGsRXsASg38wNueb8bx", :hex)
    end
  end

  describe "pytezos tests" do
    test "test_forge_combs" do
      expr = %{
        "prim" => "Pair",
        "args" => [%{"int" => "1"}, %{"int" => "2"}, %{"int" => "3"}, %{"int" => "4"}]
      }

      assert expr == Forge.unforge_micheline(Forge.forge_micheline(expr))
    end

    test "test_prim_sequence_three_args" do
      packed =
        "0502000000f003200743036e0a00000016010cd84cb6f78f1e146e5e86b3648327edfd45618e0007430368010000000c63616c6c6261636b2d343034037706550765096500000031046e0000000625766f746572045d0000000a2563616e64696461746504590000000f25657865637574655f766f74696e670000000c25766f74655f706172616d73046e00000007256275636b657400000010256c61756e63685f63616c6c6261636b072f020000000203270200000004034c03200743036a00000521000307430359030a0743035d0a00000015002523250b271e153be6c2668954114be101d04d3d05700005054200030342034d"

      data = :binary.decode_hex(packed)

      result =
        Forge.unforge_micheline(binary_slice(data, 1..-1//1))

      expected_result = [
        %{"prim" => "DROP"},
        %{
          "prim" => "PUSH",
          "args" => [
            %{"prim" => "address"},
            %{"bytes" => "010cd84cb6f78f1e146e5e86b3648327edfd45618e00"}
          ]
        },
        %{"prim" => "PUSH", "args" => [%{"prim" => "string"}, %{"string" => "callback-404"}]},
        %{"prim" => "SELF_ADDRESS"},
        %{
          "prim" => "CONTRACT",
          "args" => [
            %{
              "prim" => "pair",
              "args" => [
                %{
                  "prim" => "pair",
                  "args" => [
                    %{"prim" => "address", "annots" => ["%voter"]},
                    %{"prim" => "key_hash", "annots" => ["%candidate"]},
                    %{"prim" => "bool", "annots" => ["%execute_voting"]}
                  ],
                  "annots" => ["%vote_params"]
                },
                %{"prim" => "address", "annots" => ["%bucket"]}
              ]
            }
          ],
          "annots" => ["%launch_callback"]
        },
        %{
          "prim" => "IF_NONE",
          "args" => [[%{"prim" => "FAILWITH"}], [%{"prim" => "SWAP"}, %{"prim" => "DROP"}]]
        },
        %{"prim" => "PUSH", "args" => [%{"prim" => "mutez"}, %{"int" => "0"}]},
        %{"prim" => "DUP", "args" => [%{"int" => "3"}]},
        %{"prim" => "PUSH", "args" => [%{"prim" => "bool"}, %{"prim" => "True"}]},
        %{
          "prim" => "PUSH",
          "args" => [
            %{"prim" => "key_hash"},
            %{"bytes" => "002523250b271e153be6c2668954114be101d04d3d"}
          ]
        },
        %{"prim" => "DIG", "args" => [%{"int" => "5"}]},
        %{"prim" => "PAIR", "args" => [%{"int" => "3"}]},
        %{"prim" => "PAIR"},
        %{"prim" => "TRANSFER_TOKENS"}
      ]

      assert result == expected_result

      assert expected_result == Forge.unforge_micheline(Forge.forge_micheline(expected_result))
    end

    test "test_regr_local_remote_diff" do
      opg = %{
        "branch" => "BKpLvH3E3bUa5Z2nb3RkH2p6EKLfymvxUAEgtRJnu4m9UX1TWUb",
        "contents" => [
          %{
            "amount" => "0",
            "counter" => "446245",
            "destination" => "KT1VYUxhLoSvouozCaDGL1XcswnagNfwr3yi",
            "fee" => "104274",
            "gas_limit" => "1040000",
            "kind" => "transaction",
            "parameters" => %{"entrypoint" => "default", "value" => %{"prim" => "Unit"}},
            "source" => "tz1grSQDByRpnVs7sPtaprNZRp531ZKz6Jmm",
            "storage_limit" => "60000"
          }
        ],
        "protocol" => "PsCARTHAGazKbHtnKfLzQg3kms52kSRpgnDY982a9oYsSXRLQEb",
        "signature" => nil
      }

      local = ForgeOperation.forge_operation_group(opg)

      remote =
        "0dc397b7865779d87bd47d406e8b4eee84498f22ab01dff124433c7f057af5ae6c00e8b36c80efb51ec85a14562426049aa182a3ce38d2ae06a59e1b80bd3fe0d4030001e5ebf2dcc7dcc9d13c2c45cd76823dd604740c7f0000"

      assert local == remote
    end
  end
end
