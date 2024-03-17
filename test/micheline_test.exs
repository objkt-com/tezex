defmodule Tezex.Micheline.Test do
  use ExUnit.Case
  alias Tezex.Micheline
  doctest Tezex.Micheline

  test "Small int: hex -> Micheline" do
    assert {%{int: 6}, _} = Micheline.hex_to_micheline("0006")

    assert {%{int: -6}, _} = Micheline.hex_to_micheline("0046")

    assert {%{int: 63}, _} = Micheline.hex_to_micheline("003f")

    assert {%{int: -63}, _} = Micheline.hex_to_micheline("007f")
  end

  test "Medium int: hex -> Micheline" do
    assert {%{int: 97}, _} = Micheline.hex_to_micheline("00a101")

    assert {%{int: -127}, _} = Micheline.hex_to_micheline("00ff01")

    assert {%{int: 900}, _} = Micheline.hex_to_micheline("00840e")

    assert {%{int: -900}, _} = Micheline.hex_to_micheline("00c40e")
  end

  test "Large int: hex -> Micheline" do
    assert {%{int: 917_431_994}, _} = Micheline.hex_to_micheline("00ba9af7ea06")

    assert {%{int: -917_431_994}, _} = Micheline.hex_to_micheline("00fa9af7ea06")

    assert {%{int: 365_729}, _} = Micheline.hex_to_micheline("00a1d22c")

    assert {%{int: -365_729}, _} = Micheline.hex_to_micheline("00e1d22c")

    assert {%{int: 610_913_435_200}, _} = Micheline.hex_to_micheline("0080f9b9d4c723")

    assert {%{int: -610_913_435_200}, _} = Micheline.hex_to_micheline("00c0f9b9d4c723")
  end

  test "strings" do
    {result, 122} =
      Micheline.hex_to_micheline(
        "0100000038697066733a2f2f516d54556177504451526557325754514d6869725967416b707854427a487a616e3646465846776b685071654d6a2f3434"
      )

    assert result == %{string: "ipfs://QmTUawPDQReW2WTQMhirYgAkpxTBzHzan6FFXFwkhPqeMj/44"}
  end

  test "bytes" do
    {result, _} = Micheline.hex_to_micheline("0a000000080123456789abcdef")
    assert result == %{bytes: "0123456789abcdef"}
  end

  test "Mixed literal value array" do
    assert {[%{int: -33}, %{string: "tezos"}, %{string: ""}, %{string: "cryptonomic"}], 76} =
             Micheline.hex_to_micheline(
               "02000000210061010000000574657a6f730100000000010000000b63727970746f6e6f6d6963"
             )
  end

  test "Bare primitive" do
    assert {%{prim: "PUSH"}, 4} = Micheline.hex_to_micheline("0343")
  end

  test "Single primitive with a single annotation" do
    assert {%{annot: "@cba", prim: "PUSH"}, 20} =
             Micheline.hex_to_micheline("04430000000440636261")
  end

  test "Single primitive with a single argument" do
    {result, _} = Micheline.hex_to_micheline("053d036d")
    assert result == %{prim: "NIL", args: [%{prim: "operation"}]}
  end

  test "Single primitive with two arguments" do
    assert {%{annots: ["@cba"], args: [%{prim: "operation"}], prim: "NIL"}, 24} =
             Micheline.hex_to_micheline("063d036d0000000440636261")

    assert {%{args: [%{prim: "operation"}, %{prim: "operation"}], prim: "NIL"}, 12} =
             Micheline.hex_to_micheline("073d036d036d")
  end

  test "Single primitive with two arguments and annotation" do
    assert {%{
              annots: ["@cba"],
              args: [%{prim: "operation"}, %{prim: "operation"}],
              prim: "NIL"
            }, 28} = Micheline.hex_to_micheline("083d036d036d0000000440636261")
  end

  test "Single primitive with more than two arguments and no annotations" do
    assert {%{
              args: [%{prim: "operation"}, %{prim: "operation"}, %{prim: "operation"}],
              prim: "NIL"
            }, 32} = Micheline.hex_to_micheline("093d00000006036d036d036d00000000")
  end

  test "Single primitive with more than two arguments and multiple annotations" do
    assert {%{
              annots: ["@red", "@green", "@blue"],
              args: [%{prim: "operation"}, %{prim: "operation"}, %{prim: "operation"}],
              prim: "NIL"
            },
            66} =
             Micheline.hex_to_micheline(
               "093d00000006036d036d036d00000011407265642040677265656e2040626c7565"
             )
  end

  test "Encode/decode string" do
    assert "050100000003666F6F" == Micheline.string_to_micheline_hex("foo")
    s = "0100000003666F6F"
    assert {%{string: "foo"}, byte_size(s)} == Micheline.hex_to_micheline(s)
  end
end
