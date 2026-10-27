defmodule Tezex.MichelsonTest do
  use ExUnit.Case, async: true

  alias Tezex.Crypto.Base58Check
  alias Tezex.Crypto.BLS
  alias Tezex.Michelson
  alias Tezex.Michelson.EncodeError

  doctest Tezex.Michelson, import: true

  # Octez base58 prefixes (src/lib_crypto/base58.ml, contract_hash.ml).
  @tz1 <<6, 161, 159>>
  @tz2 <<6, 161, 161>>
  @tz3 <<6, 161, 164>>
  @tz4 <<6, 161, 166>>
  @kt1 <<2, 90, 121>>
  @sr1 <<6, 124, 117>>
  @edpk <<13, 15, 37, 217>>
  @sppk <<3, 254, 226, 86>>
  @p2pk <<3, 178, 139, 127>>
  @blpk <<6, 149, 135, 204>>
  @edsig <<9, 245, 205, 134, 18>>
  @spsig <<13, 115, 101, 19, 63>>
  @p2sig <<54, 240, 44, 52>>
  @sig <<4, 130, 43>>
  @blsig <<40, 171, 64, 207>>
  @net <<87, 82, 0>>

  @tz1_a "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew"
  @tz1_b "tz1cMcDFLgFe2picQbo4DY1i6mZJiVhPCu5B"
  @tz2_a "tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx"
  @tz3_a "tz3bPFa6mGv8m4Ppn7w5KSDyAbEPwbJNpC9p"
  @tz4_a "tz4NWRt3aFyFU2Ydah917Eehxv6uf97j8tpZ"
  @kt1_a "KT1UErZCry4DLRwqwWon5tECgpKRaMfQ5yEP"
  @kt1_b "KT1PWx2mnDueood7fEmfbBDKx1D9BAnnXitn"

  @edpk_a "edpktsPhZ8weLEXqf4Fo5FS9Qx8ZuX4QpEBEwe63L747G8iDjTAF6w"
  @sppk_a "sppk7aBerAEA6tv4wzg6FnK7i5YrGtEGFVvNjWhc2QX8bhzpouBVFSW"
  @p2pk_a "p2pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa"
  @blpk_a "BLpk1nuQ6M54P2zN2gX2maUUzRa3QVX2eSnXZa184g2sfu2qB2XCGYJdZezkgb7ozbbfYUny1gcP"

  @edsig_a "edsigtqqVg7CM2ynDXRHUfVEdL4LxKAJ1xrM1poMPXZdwVQ3SQ6YBkqPcAuaGYbeqUTrg374dDNFvJKCVfMA7T1Vrotg91Hsuam"
  @edsig_b "edsigtv33HXjUxCSgs8SQ3DMpmJ1eVtAShY3RcSd1L9K1Y5pJnUm3Fg5eF2fHgX1NdaSKc5yGo5T5C6VYpj7nUJvi62TWdf8Fco"
  @spsig_a "spsig1ZNQaUKNERZSiEiNviqa5EAPkcNASXhfkXtxRatZTDZAnUB4Ra2Jus8b1oEpFnPx8Z6g28pd8vK3R8nPK29JDU5FiSLH5T"
  @spsig_b "spsig1EjqdcNBd2jn2QB8Btn9ZujBBi3pUULPRh8nTx4ACPSQLZKSHh4ihM9BdQ7uPCx5MaZd6gpErzXnUijRSd3E8BqcK5XHrg"
  @spsig_c "spsig1W2NuFBUoFgPcATxbcHKkRqqakqwzYcunA84XPPnUK8UJydRFr8tChq87YTYpyknba5Bzj7jenYcKVAYRPgqXpy9QtPYNT"
  @p2sig_a "p2sigNdsHrSzfc7oQMFjrbXFiZe3SM4329j1VY6GYY7kRG6Q4L4Ljw1gT4wKRrRqDECxQwTfs967gpe4EDQJo6cSgB79TmFCfg"
  @p2sig_b "p2sigkXYeimNtVJDr8X3me62Rig7cPogEQ3NPYHcGgnGuuFFy2BqttXHnst3mYyJ68k3jdAE92TKbyGC9hcmmVy1YbxyTJXAc1"
  @sig_a "sigtofRkQAsLW8ne1HcGhbuBg2Ja2Yt9A2gfpwZFBsdjRWLPSVVqN9BVRpGr7DMwz1e4WjyF8iAjpf1LKyZMcJTSPrDaRzsx"
  @blsig_a "BLsigBCNyUiH3Z5rtuWLyeRutnjeDSiZTcC1owGxXBEJUnfcAaCTciHLjH3asupDYbeu5NvmuUdKyV9r6DHhXQF2w1qiYo4tPVX11v9HnrracZ9DeZdeo8bKyHDDYDVVh4neP36Rs5iM26"

  @chain_id "NetXsqzbfFenSTS"

  @typecheck_url "https://rpc.shadownet.teztnets.com/chains/main/blocks/head/helpers/scripts/typecheck_data"

  @unit %{"prim" => "Unit"}
  @none %{"prim" => "None"}
  @true_ %{"prim" => "True"}
  @false_ %{"prim" => "False"}

  describe "handoff table" do
    test "pair nat nat: {1, 2} is Pair 1 2" do
      type = ty("pair", [ty("nat"), ty("nat")])
      assert {:ok, pair(int(1), int(2))} == Michelson.encode(type, {1, 2})
    end

    test "pair (nat %a) nat: {1, 2} is Pair 1 2" do
      type = ty("pair", [ann(ty("nat"), "a"), ty("nat")])
      assert {:ok, pair(int(1), int(2))} == Michelson.encode(type, {1, 2})
    end

    test "pair nat (pair nat nat): {10, {11, 12}} and {10, 11, 12} are Pair 10 (Pair 11 12)" do
      type = ty("pair", [ty("nat"), ty("pair", [ty("nat"), ty("nat")])])
      expected = pair(int(10), pair(int(11), int(12)))

      assert {:ok, expected} == Michelson.encode(type, {10, {11, 12}})
      assert {:ok, expected} == Michelson.encode(type, {10, 11, 12})
    end

    test "or (unit %tez) (address %fa12): :tez is Left Unit" do
      assert {:ok, left(@unit)} == Michelson.encode(tez_or_fa12(), :tez)
    end

    test "or (unit %tez) (address %fa12): {:fa12, KT1} is Right KT1" do
      assert {:ok, right(str(@kt1_a))} == Michelson.encode(tez_or_fa12(), {:fa12, @kt1_a})
    end

    test "or nat string: {:left, 1} is Left 1" do
      type = ty("or", [ty("nat"), ty("string")])
      assert {:ok, left(int(1))} == Michelson.encode(type, {:left, 1})
    end

    test "or nat (or string bool): {:right, {:right, true}} is Right (Right True)" do
      type = ty("or", [ty("nat"), ty("or", [ty("string"), ty("bool")])])
      assert {:ok, right(right(@true_))} == Michelson.encode(type, {:right, {:right, true}})
    end

    test "map (pair nat nat) nat: %{{1, 2} => 5} is {Elt (Pair 1 2) 5}" do
      type = ty("map", [ty("pair", [ty("nat"), ty("nat")]), ty("nat")])
      assert {:ok, [elt(pair(int(1), int(2)), int(5))]} == Michelson.encode(type, %{{1, 2} => 5})
    end
  end

  describe "unit" do
    test "accepts :unit" do
      assert {:ok, @unit} == Michelson.encode(ty("unit"), :unit)
    end

    test "rejects anything else" do
      assert_error(ty("unit"), nil, :invalid_value, [])
      assert_error(ty("unit"), %{}, :invalid_value, [])
    end
  end

  describe "bool" do
    test "accepts true and false" do
      assert {:ok, @true_} == Michelson.encode(ty("bool"), true)
      assert {:ok, @false_} == Michelson.encode(ty("bool"), false)
    end

    test "rejects a string" do
      assert_error(ty("bool"), "true", :invalid_value, [])
    end
  end

  describe "int" do
    test "accepts negative, zero and big integers" do
      assert {:ok, int(-5)} == Michelson.encode(ty("int"), -5)
      assert {:ok, int(0)} == Michelson.encode(ty("int"), 0)

      assert {:ok, %{"int" => "1267650600228229401496703205376"}} ==
               Michelson.encode(ty("int"), 2 ** 100)
    end

    test "rejects numeric strings and floats (integers only)" do
      assert_error(ty("int"), "1", :invalid_value, [])
      assert_error(ty("int"), 1.0, :invalid_value, [])
    end
  end

  describe "nat" do
    test "accepts 0 and a positive integer" do
      assert {:ok, int(0)} == Michelson.encode(ty("nat"), 0)
      assert {:ok, %{"int" => "1500000"}} == Michelson.encode(ty("nat"), 1_500_000)
    end

    test "rejects a negative integer" do
      assert_error(ty("nat"), -1, :invalid_value, [])
    end

    test "rejects a decimal string" do
      assert_error(ty("nat"), "1500000", :invalid_value, [])
    end

    test "the error carries the rejected value" do
      assert {:error, %EncodeError{value: -1}} = Michelson.encode(ty("nat"), -1)
    end
  end

  describe "mutez" do
    test "accepts 0 and 2^63 - 1" do
      assert {:ok, int(0)} == Michelson.encode(ty("mutez"), 0)

      assert {:ok, %{"int" => "9223372036854775807"}} ==
               Michelson.encode(ty("mutez"), 2 ** 63 - 1)
    end

    test "rejects 2^63" do
      assert_error(ty("mutez"), 2 ** 63, :invalid_value, [])
    end

    test "rejects a negative integer" do
      assert_error(ty("mutez"), -1, :invalid_value, [])
    end
  end

  describe "string" do
    test "accepts printable ASCII and newlines" do
      assert {:ok, str("hello\nworld")} == Michelson.encode(ty("string"), "hello\nworld")
      assert {:ok, str(" ~")} == Michelson.encode(ty("string"), " ~")
      assert {:ok, str("")} == Michelson.encode(ty("string"), "")
    end

    test "rejects a tab" do
      assert_error(ty("string"), "a\tb", :invalid_value, [])
    end

    test "rejects a carriage return" do
      assert_error(ty("string"), "a\rb", :invalid_value, [])
    end

    test "rejects DEL (127)" do
      assert_error(ty("string"), <<127>>, :invalid_value, [])
    end

    test "rejects non-ASCII" do
      assert_error(ty("string"), "café", :invalid_value, [])
    end

    test "rejects a non-binary" do
      assert_error(ty("string"), :hello, :invalid_value, [])
    end
  end

  describe "bytes-like types" do
    test "bytes: raw binary becomes lowercase hex" do
      assert {:ok, %{"bytes" => "ab01"}} == Michelson.encode(ty("bytes"), <<0xAB, 0x01>>)
      assert {:ok, %{"bytes" => ""}} == Michelson.encode(ty("bytes"), <<>>)
    end

    test "bytes: rejects a non-binary" do
      assert_error(ty("bytes"), 5, :invalid_value, [])
    end

    test "bls12_381_*, chest, chest_key, sapling_transaction take raw binaries" do
      cases = [
        {ty("bls12_381_g1"), :binary.copy(<<0xAB>>, 96)},
        {ty("bls12_381_g2"), :binary.copy(<<0xCD>>, 192)},
        {ty("bls12_381_fr"), :binary.copy(<<0x01>>, 32)},
        {ty("chest"), <<0xDE, 0xAD>>},
        {ty("chest_key"), <<0xBE, 0xEF>>},
        {ty("sapling_transaction", [int(8)]), <<0xCA, 0xFE>>}
      ]

      for {type, value} <- cases do
        assert {:ok, %{"bytes" => Base.encode16(value, case: :lower)}} ==
                 Michelson.encode(type, value),
               "for #{type["prim"]}"

        assert_error(type, 5, :invalid_value, [])
      end
    end
  end

  describe "address" do
    test "accepts implicit, originated and rollup addresses" do
      for address <- [@tz1_a, @tz2_a, @tz3_a, @tz4_a, @kt1_a, sr1(:binary.copy(<<0>>, 20))] do
        assert {:ok, str(address)} == Michelson.encode(ty("address"), address)
      end
    end

    test "accepts an %entrypoint suffix" do
      address = @kt1_a <> "%transfer"
      assert {:ok, str(address)} == Michelson.encode(ty("address"), address)
    end

    test "accepts a 31-character entrypoint" do
      address = @kt1_a <> "%" <> String.duplicate("a", 31)
      assert {:ok, str(address)} == Michelson.encode(ty("address"), address)
    end

    test "rejects a 32-character entrypoint" do
      address = @kt1_a <> "%" <> String.duplicate("a", 32)
      assert_error(ty("address"), address, :invalid_value, [])
    end

    test "rejects %default" do
      assert_error(ty("address"), @kt1_a <> "%default", :invalid_value, [])
    end

    test "rejects a bad base58 checksum" do
      assert_error(ty("address"), break_checksum(@tz1_a), :invalid_value, [])
    end

    test "rejects a base58 value that isn't an address" do
      assert_error(ty("address"), @edpk_a, :invalid_value, [])
    end

    test "rejects a non-string" do
      assert_error(ty("address"), 42, :invalid_value, [])
    end
  end

  describe "contract" do
    test "accepts an address with and without entrypoint" do
      type = ty("contract", [ty("nat")])
      assert {:ok, str(@kt1_a)} == Michelson.encode(type, @kt1_a)
      assert {:ok, str(@kt1_a <> "%mint")} == Michelson.encode(type, @kt1_a <> "%mint")
    end

    test "rejects %default and a bad checksum" do
      type = ty("contract", [ty("nat")])
      assert_error(type, @kt1_a <> "%default", :invalid_value, [])
      assert_error(type, break_checksum(@kt1_a), :invalid_value, [])
    end
  end

  describe "key_hash" do
    test "accepts tz1, tz2, tz3, tz4" do
      for kh <- [@tz1_a, @tz2_a, @tz3_a, @tz4_a] do
        assert {:ok, str(kh)} == Michelson.encode(ty("key_hash"), kh)
      end
    end

    test "rejects a KT1, a bad checksum and garbage" do
      assert_error(ty("key_hash"), @kt1_a, :invalid_value, [])
      assert_error(ty("key_hash"), break_checksum(@tz1_a), :invalid_value, [])
      assert_error(ty("key_hash"), "tz1nope", :invalid_value, [])
    end
  end

  describe "key" do
    test "accepts edpk, sppk, p2pk and BLpk" do
      for key <- [@edpk_a, @sppk_a, @p2pk_a, @blpk_a] do
        assert {:ok, str(key)} == Michelson.encode(ty("key"), key)
      end
    end

    test "rejects an address, a bad checksum and a truncated key" do
      assert_error(ty("key"), @tz1_a, :invalid_value, [])
      assert_error(ty("key"), break_checksum(@edpk_a), :invalid_value, [])
      assert_error(ty("key"), String.slice(@edpk_a, 0, 40), :invalid_value, [])
    end
  end

  describe "signature" do
    test "accepts edsig, spsig1, p2sig, sig and BLsig" do
      for signature <- [@edsig_a, @spsig_a, @p2sig_a, @sig_a, @blsig_a] do
        assert {:ok, str(signature)} == Michelson.encode(ty("signature"), signature)
      end
    end

    test "rejects a key and a bad checksum" do
      assert_error(ty("signature"), @edpk_a, :invalid_value, [])
      assert_error(ty("signature"), break_checksum(@edsig_a), :invalid_value, [])
    end
  end

  describe "chain_id" do
    test "accepts a Net… chain id" do
      assert {:ok, str(@chain_id)} == Michelson.encode(ty("chain_id"), @chain_id)
    end

    test "rejects a bad checksum, garbage and an address" do
      assert_error(ty("chain_id"), break_checksum(@chain_id), :invalid_value, [])
      assert_error(ty("chain_id"), "NetXbad", :invalid_value, [])
      assert_error(ty("chain_id"), @tz1_a, :invalid_value, [])
    end
  end

  describe "timestamp" do
    test "a UTC DateTime is an RFC3339 UTC string" do
      assert {:ok, str("2026-07-29T10:00:00Z")} ==
               Michelson.encode(ty("timestamp"), ~U[2026-07-29 10:00:00Z])
    end

    test "a DateTime with an offset is output in UTC" do
      paris = %DateTime{
        year: 2026,
        month: 7,
        day: 29,
        hour: 12,
        minute: 0,
        second: 0,
        microsecond: {0, 0},
        time_zone: "Europe/Paris",
        zone_abbr: "CEST",
        utc_offset: 3600,
        std_offset: 3600
      }

      assert {:ok, str("2026-07-29T10:00:00Z")} == Michelson.encode(ty("timestamp"), paris)
    end

    test "a DateTime with millisecond precision but zero fraction is whole seconds" do
      assert {:ok, str("2026-07-29T10:00:00Z")} ==
               Michelson.encode(ty("timestamp"), ~U[2026-07-29 10:00:00.000Z])
    end

    test "rejects a DateTime with microseconds" do
      assert_error(ty("timestamp"), ~U[2026-07-29 10:00:00.123456Z], :invalid_value, [])
    end

    test "rejects a string" do
      assert_error(ty("timestamp"), "2026-07-29T10:00:00Z", :invalid_value, [])
    end
  end

  describe "list" do
    test "keeps the given order" do
      assert {:ok, [int(2), int(1), int(2)]} ==
               Michelson.encode(ty("list", [ty("nat")]), [2, 1, 2])
    end

    test "rejects a non-list" do
      assert_error(ty("list", [ty("nat")]), MapSet.new([1]), :invalid_value, [])
    end

    test "an element error has the element's position" do
      assert_error(ty("list", [ty("nat")]), [1, -1], :invalid_value, [1])
    end

    test "rejects an improper list" do
      assert_error(ty("list", [ty("nat")]), [1 | 2], :invalid_value, [])
      assert_error(ty("list", [ty("nat")]), [1, 2 | 3], :invalid_value, [])
    end

    test "encodes a list of named pairs in order" do
      type =
        ty("list", [
          ty("pair", [ann(ty("address"), "recipient"), ann(ty("nat"), "amount")])
        ])

      value = [%{recipient: @tz1_a, amount: 500}, %{recipient: @tz1_b, amount: 250}]

      assert {:ok, [pair(str(@tz1_a), int(500)), pair(str(@tz1_b), int(250))]} ==
               Michelson.encode(type, value)
    end
  end

  describe "set" do
    test "accepts a list and a MapSet" do
      type = ty("set", [ty("nat")])
      assert {:ok, [int(1), int(129), int(256)]} == Michelson.encode(type, [256, 1, 129])
      assert {:ok, [int(1), int(2), int(3)]} == Michelson.encode(type, MapSet.new([3, 1, 2]))
    end

    test "rejects a map" do
      assert_error(ty("set", [ty("nat")]), %{1 => 1}, :invalid_value, [])
    end

    test "an element error has a {:key, element} segment" do
      assert_error(ty("set", [ty("nat")]), [1, -1], :invalid_value, [{:key, -1}])
    end

    test "rejects an improper list" do
      assert_error(ty("set", [ty("nat")]), [1 | 2], :invalid_value, [])
    end
  end

  describe "map" do
    test "an empty map is an empty sequence" do
      assert {:ok, []} == Michelson.encode(ty("map", [ty("address"), ty("nat")]), %{})
    end

    test "sorts address keys implicit before originated (ported)" do
      type = ty("map", [ty("address"), ty("nat")])

      assert {:ok, [elt(str(@tz1_a), int(70)), elt(str(@kt1_a), int(30))]} ==
               Michelson.encode(type, %{@kt1_a => 30, @tz1_a => 70})
    end

    test "rejects a keyword list" do
      assert_error(ty("map", [ty("nat"), ty("nat")]), [{1, 2}], :invalid_value, [])
    end

    test "a value error has a {:value, key} segment" do
      assert_error(ty("map", [ty("nat"), ty("nat")]), %{1 => -1}, :invalid_value, [{:value, 1}])
    end

    test "a key error has a {:key, key} segment" do
      assert_error(ty("map", [ty("nat"), ty("nat")]), %{-1 => 1}, :invalid_value, [{:key, -1}])
    end

    test "a key type with no ordering is not_comparable" do
      type = ty("map", [ty("list", [ty("nat")]), ty("nat")])

      assert {:error, %EncodeError{reason: :not_comparable}} =
               Michelson.encode(type, %{[1] => 0, [2] => 0})
    end
  end

  describe "big_map" do
    test "accepts a map" do
      type = ty("big_map", [ty("string"), ty("nat")])

      assert {:ok, [elt(str("a"), int(1)), elt(str("b"), int(2))]} ==
               Michelson.encode(type, %{"b" => 2, "a" => 1})
    end

    test "rejects a big_map id" do
      assert_error(ty("big_map", [ty("string"), ty("nat")]), 42, :invalid_value, [])
    end
  end

  describe "lambda" do
    test "passes the code through as is" do
      type = ty("lambda", [ty("nat"), ty("nat")])
      code = [%{"prim" => "PUSH", "args" => [ty("nat"), int(1)]}, %{"prim" => "ADD"}]
      assert {:ok, code} == Michelson.encode(type, code)
    end
  end

  describe "sapling_state" do
    test "accepts only the empty state []" do
      type = ty("sapling_state", [int(8)])
      assert {:ok, []} == Michelson.encode(type, [])
      assert_error(type, [<<1>>], :invalid_value, [])
    end
  end

  describe "never, operation, ticket" do
    test "never has no values" do
      assert {:error, %EncodeError{reason: reason, path: []}} =
               Michelson.encode(ty("never"), :unit)

      assert reason in [:invalid_value, :not_passable]
    end

    test "an empty set of never is fine" do
      assert {:ok, []} == Michelson.encode(ty("set", [ty("never")]), [])
    end

    test "operation is not passable" do
      assert_error(ty("operation"), [], :not_passable, [])
    end

    test "ticket is an error" do
      assert {:error, %EncodeError{reason: reason, path: []}} =
               Michelson.encode(ty("ticket", [ty("nat")]), {@kt1_a, 1, 1})

      assert reason in [:not_passable, :unsupported_type]
    end

    test "the error path points inside a pair" do
      type = ty("pair", [ann(ty("operation"), "op"), ann(ty("nat"), "n")])

      assert {:error, %EncodeError{reason: :not_passable, path: ["op"]}} =
               Michelson.encode(type, %{op: [], n: 1})
    end
  end

  describe "option" do
    test "nil is None, a value is Some" do
      type = ty("option", [ty("nat")])
      assert {:ok, @none} == Michelson.encode(type, nil)
      assert {:ok, some(int(5))} == Michelson.encode(type, 5)
      assert {:ok, some(int(0))} == Michelson.encode(type, 0)
    end

    test "{:some, v} is rejected when the type inside isn't an option" do
      assert {:error, %EncodeError{}} = Michelson.encode(ty("option", [ty("nat")]), {:some, 5})
    end

    test "option (option nat): nil, {:some, nil}, 5, {:some, 5}" do
      type = ty("option", [ty("option", [ty("nat")])])
      assert {:ok, @none} == Michelson.encode(type, nil)
      assert {:ok, some(@none)} == Michelson.encode(type, {:some, nil})
      assert {:ok, some(some(int(5)))} == Michelson.encode(type, 5)
      assert {:ok, some(some(int(5)))} == Michelson.encode(type, {:some, 5})
    end

    test "an invalid Some value is reported at the option's path" do
      type = ty("pair", [ann(ty("option", [ty("nat")]), "expiry"), ann(ty("nat"), "n")])
      assert_error(type, %{expiry: -1, n: 1}, :invalid_value, ["expiry"])
    end

    for {label, option_type} <- [
          {"on the option",
           %{"prim" => "option", "annots" => ["%expiry"], "args" => [%{"prim" => "nat"}]}},
          {"on the inner type",
           %{"prim" => "option", "args" => [%{"prim" => "nat", "annots" => ["%expiry"]}]}}
        ] do
      @option_type option_type

      test "name #{label}: missing key is None" do
        type = ty("pair", [@option_type, ann(ty("nat"), "n")])
        assert {:ok, pair(@none, int(1))} == Michelson.encode(type, %{n: 1})
      end

      test "name #{label}: nil is None" do
        type = ty("pair", [@option_type, ann(ty("nat"), "n")])
        assert {:ok, pair(@none, int(1))} == Michelson.encode(type, %{expiry: nil, n: 1})
      end

      test "name #{label}: a value is Some" do
        type = ty("pair", [@option_type, ann(ty("nat"), "n")])
        assert {:ok, pair(some(int(60)), int(1))} == Michelson.encode(type, %{expiry: 60, n: 1})
      end
    end
  end

  describe "pair as map" do
    test "atom keys" do
      assert {:ok, pair(str(@tz1_a), int(5))} ==
               Michelson.encode(holder_amount(), %{holder: @tz1_a, amount: 5})
    end

    test "string keys" do
      assert {:ok, pair(str(@tz1_a), int(5))} ==
               Michelson.encode(holder_amount(), %{"holder" => @tz1_a, "amount" => 5})
    end

    test "a fully named pair rejects a tuple" do
      assert_error(holder_amount(), {@tz1_a, 5}, :invalid_value, [])
    end

    test "the same name as atom and string is an error" do
      value = %{:holder => @tz1_a, :amount => 5, "amount" => 6}
      assert_error(holder_amount(), value, :duplicate_field, ["amount"])
    end

    test "an unknown key is an error" do
      value = %{holder: @tz1_a, amount: 5, bogus: 1}
      assert_error(holder_amount(), value, :unknown_field, ["bogus"])
    end

    test "a missing non-option field is an error with its path" do
      assert {:error, %EncodeError{reason: :missing_field, path: ["amount"], value: nil}} =
               Michelson.encode(holder_amount(), %{holder: @tz1_a})
    end

    test "a field error has the field name in the path" do
      assert_error(holder_amount(), %{holder: @tz1_a, amount: -5}, :invalid_value, ["amount"])
    end

    test "unnamed nested pairs are flattened into one map" do
      type =
        ty("pair", [
          ann(ty("nat"), "a"),
          ty("pair", [ann(ty("nat"), "b"), ann(ty("nat"), "c")])
        ])

      assert {:ok, pair(int(1), pair(int(2), int(3)))} ==
               Michelson.encode(type, %{a: 1, b: 2, c: 3})
    end

    test "an n-ary named pair is a flat map and outputs nested binary Pair" do
      type = ty("pair", [ann(ty("nat"), "a"), ann(ty("nat"), "b"), ann(ty("nat"), "c")])

      assert {:ok, pair(int(1), pair(int(2), int(3)))} ==
               Michelson.encode(type, %{a: 1, b: 2, c: 3})
    end

    test "a named nested pair is a nested map" do
      assert {:ok, pair(pair(str(@kt1_a), int(7)), int(1))} ==
               Michelson.encode(token_editions(), %{
                 token: %{address: @kt1_a, token_id: 7},
                 editions: 1
               })
    end

    test "an error in a named nested pair has the nested path" do
      value = %{token: %{address: @kt1_a}, editions: 1}

      assert {:error, %EncodeError{reason: :missing_field, path: ["token", "token_id"]}} =
               Michelson.encode(token_editions(), value)
    end

    test "two fields sharing a name make the pair a tuple" do
      type = ty("pair", [ann(ty("nat"), "a"), ann(ty("nat"), "a")])
      assert {:ok, pair(int(1), int(2))} == Michelson.encode(type, {1, 2})
      assert {:error, %EncodeError{}} = Michelson.encode(type, %{a: 1})
    end

    test ":type annotations are not names" do
      type =
        ty("pair", [
          %{"prim" => "nat", "annots" => [":a"]},
          %{"prim" => "nat", "annots" => [":b"]}
        ])

      assert {:ok, pair(int(1), int(2))} == Michelson.encode(type, {1, 2})
    end
  end

  describe "pair as tuple" do
    test "a partly named pair takes a flat tuple" do
      type = ty("pair", [ann(ty("nat"), "a"), ty("pair", [ty("nat"), ty("nat")])])
      assert {:ok, pair(int(1), pair(int(2), int(3)))} == Michelson.encode(type, {1, 2, 3})
    end

    test "pair a b c (3 args) takes flat and nested tuples" do
      type = ty("pair", [ty("nat"), ty("nat"), ty("nat")])
      expected = pair(int(1), pair(int(2), int(3)))

      assert {:ok, expected} == Michelson.encode(type, {1, 2, 3})
      assert {:ok, expected} == Michelson.encode(type, {1, {2, 3}})
    end

    test "a 4-field comb takes a partly flattened tuple" do
      type = ty("pair", [ty("nat"), ty("pair", [ty("nat"), ty("pair", [ty("nat"), ty("nat")])])])
      expected = pair(int(1), pair(int(2), pair(int(3), int(4))))

      assert {:ok, expected} == Michelson.encode(type, {1, 2, 3, 4})
      assert {:ok, expected} == Michelson.encode(type, {1, 2, {3, 4}})
      assert {:ok, expected} == Michelson.encode(type, {1, {2, {3, 4}}})
    end

    test "a tuple that is too long is an error" do
      type = ty("pair", [ty("nat"), ty("nat"), ty("nat")])
      assert_error(type, {1, 2, 3, 4}, :invalid_value, [])
    end

    test "a tuple that is too short is an error" do
      type = ty("pair", [ty("nat"), ty("nat"), ty("nat")])
      assert_error(type, {1}, :invalid_value, [])
    end

    test "the last element must cover the rest of the comb" do
      type = ty("pair", [ty("nat"), ty("nat"), ty("nat")])
      assert_error(type, {1, 2}, :invalid_value, [1])
    end

    test "an element error has its position in the flat tuple" do
      type = ty("pair", [ty("nat"), ty("nat"), ty("nat")])
      assert_error(type, {1, 2, -3}, :invalid_value, [2])
    end

    test "an element error has its position in the nested tuple" do
      type = ty("pair", [ty("nat"), ty("nat"), ty("nat")])
      assert_error(type, {1, {2, -3}}, :invalid_value, [1, 1])
    end

    test "rejects a positional map (Taquito's %{\"0\" => …})" do
      type = ty("pair", [ty("nat"), ty("nat")])
      assert {:error, %EncodeError{}} = Michelson.encode(type, %{"0" => 1, "1" => 2})
    end
  end

  describe "or" do
    test "a unit branch by bare name, or {name, :unit}" do
      assert {:ok, left(@unit)} == Michelson.encode(token_kind(), :tez)
      assert {:ok, left(@unit)} == Michelson.encode(token_kind(), {:tez, :unit})
    end

    test "a named branch through an unnamed nested or" do
      assert {:ok, right(left(str(@kt1_b)))} == Michelson.encode(token_kind(), {:fa12, @kt1_b})
    end

    test "a named pair branch takes a map" do
      assert {:ok, right(right(pair(str(@kt1_a), int(3))))} ==
               Michelson.encode(token_kind(), {:fa2, %{address: @kt1_a, token_id: 3}})
    end

    test "names as strings, as schema/1 shows them" do
      assert {:ok, left(@unit)} == Michelson.encode(token_kind(), "tez")
      assert {:ok, right(left(str(@kt1_b)))} == Michelson.encode(token_kind(), {"fa12", @kt1_b})
    end

    test "names through nested unnamed ors on the left" do
      type = ty("or", [ty("or", [ann(ty("nat"), "a"), ann(ty("nat"), "b")]), ty("nat")])
      assert {:ok, left(left(int(1)))} == Michelson.encode(type, {:a, 1})
      assert {:ok, left(right(int(2)))} == Michelson.encode(type, {:b, 2})
      assert {:ok, right(int(3))} == Michelson.encode(type, {:right, 3})
    end

    test ":left and :right for unnamed unit branches" do
      type = ty("or", [ty("unit"), ty("unit")])
      assert {:ok, left(@unit)} == Michelson.encode(type, :left)
      assert {:ok, right(@unit)} == Michelson.encode(type, :right)
    end

    test "an unknown branch is an error" do
      assert_error(token_kind(), {:doge, :unit}, :unknown_branch, [])
      assert_error(token_kind(), :doge, :unknown_branch, [])
    end

    test "an unknown branch inside a pair has the field path" do
      type = ty("pair", [ann(token_kind(), "currency"), ann(ty("nat"), "n")])
      assert_error(type, %{currency: :doge, n: 1}, :unknown_branch, ["currency"])
    end

    test "a bare name for a non-unit branch is an error" do
      assert {:error, %EncodeError{reason: :invalid_value}} =
               Michelson.encode(token_kind(), :fa12)
    end

    test ":left is ambiguous in or nat (nat %left)" do
      type = ty("or", [ty("nat"), ann(ty("nat"), "left")])
      assert_error(type, {:left, 1}, :ambiguous_branch, [])
    end

    test "an error under a positional branch has :left/:right in the path" do
      type = ty("or", [ty("nat"), ty("or", [ty("string"), ty("nat")])])
      assert_error(type, {:right, {:right, -1}}, :invalid_value, [:right, :right])
    end

    test "an error under a named branch has the name in the path" do
      assert_error(token_kind(), {:fa12, "nope"}, :invalid_value, ["fa12"])
    end

    test "rejects Taquito's %{tez: %{}}" do
      assert {:error, %EncodeError{}} = Michelson.encode(token_kind(), %{tez: %{}})
    end
  end

  describe "ordering" do
    test "int: numeric, with negatives and values beyond 64 bits" do
      values = [2 ** 64, -(2 ** 64), 0, -1, 1, 2 ** 53 + 1, 2 ** 53]
      assert_set_order(ty("int"), values, Enum.sort(values), &int/1)
    end

    test "nat: numeric, not by forged zarith bytes (ported)" do
      assert_set_order(ty("nat"), [1, 256, 129], [1, 129, 256], &int/1)
    end

    test "mutez: numeric" do
      assert_set_order(ty("mutez"), [10, 2 ** 63 - 1, 0], [0, 10, 2 ** 63 - 1], &int/1)
    end

    test "string: byte order, prefix first" do
      values = ["b", "aa", "a", "", "B", "a\n"]
      assert_set_order(ty("string"), values, ["", "B", "a", "a\n", "aa", "b"], &str/1)
    end

    test "bytes: byte order, prefix first" do
      values = [<<2>>, <<1, 0>>, <<1>>, <<>>, <<1, 255>>]
      expected = [<<>>, <<1>>, <<1, 0>>, <<1, 255>>, <<2>>]
      assert_set_order(ty("bytes"), values, expected, &hex/1)
    end

    test "bool: False < True" do
      assert {:ok, [@false_, @true_]} == Michelson.encode(ty("set", [ty("bool")]), [true, false])
    end

    test "unit: one element" do
      assert {:ok, [@unit]} == Michelson.encode(ty("set", [ty("unit")]), [:unit])
    end

    test "chain_id: byte order" do
      ids =
        for raw <- [<<255, 0, 0, 0>>, <<0, 0, 0, 1>>, <<0, 0, 1, 0>>, <<128, 0, 0, 0>>],
            do: {raw, b58(raw, @net)}

      expected = ids |> Enum.sort() |> Enum.map(&elem(&1, 1))
      assert_set_order(ty("chain_id"), Enum.map(ids, &elem(&1, 1)), expected, &str/1)
    end

    test "key_hash: tz1 < tz2 < tz3 < tz4, then hash bytes" do
      expected = [
        b58(h20(0x00), @tz1),
        b58(h20(0xFF), @tz1),
        b58(h20(0x00), @tz2),
        b58(h20(0xFF), @tz2),
        b58(h20(0x00), @tz3),
        b58(h20(0x00), @tz4),
        b58(h20(0xFF), @tz4)
      ]

      assert_set_order(ty("key_hash"), Enum.reverse(expected), expected, &str/1)
    end

    test "address: destination kind, then hash, then entrypoint with none meaning \"default\"" do
      expected = address_order()
      assert_set_order(ty("address"), Enum.reverse(expected), expected, &str/1)
    end

    test "address: a KT1 without entrypoint sorts after KT1%abc (not forged-byte order)" do
      assert_set_order(
        ty("address"),
        [@kt1_a, @kt1_a <> "%abc"],
        [@kt1_a <> "%abc", @kt1_a],
        &str/1
      )
    end

    test "address: map keys sorted the same way" do
      expected = address_order()
      value = expected |> Enum.with_index() |> Map.new()
      type = ty("map", [ty("address"), ty("nat")])

      assert {:ok, elts} = Michelson.encode(type, value)
      assert expected == Enum.map(elts, fn %{"args" => [%{"string" => k}, _]} -> k end)
    end

    test "key: ed25519 < secp256k1 < p256 < bls, then bytes; p256 by uncompressed point" do
      {input, expected} = key_order()
      assert_set_order(ty("key"), input, expected, &str/1)
    end

    test "signature: raw bytes, whatever the prefix" do
      expected = [
        b58(<<0x05>> <> :binary.copy(<<0>>, 95), @blsig),
        b58(<<0x10>> <> :binary.copy(<<0>>, 63), @spsig),
        b58(<<0x20>> <> :binary.copy(<<0>>, 63), @p2sig),
        b58(<<0x30>> <> :binary.copy(<<0>>, 63), @edsig),
        b58(<<0x30>> <> :binary.copy(<<1>>, 63), @sig),
        b58(<<0x40>> <> :binary.copy(<<0>>, 63), @sig)
      ]

      assert_set_order(ty("signature"), Enum.reverse(expected), expected, &str/1)
    end

    test "timestamp: by seconds, including before 1970" do
      values = [
        ~U[2100-01-01 00:00:00Z],
        ~U[1970-01-01 00:00:00Z],
        ~U[2026-07-29 10:00:00Z],
        ~U[1969-12-31 23:59:59Z]
      ]

      expected = [
        "1969-12-31T23:59:59Z",
        "1970-01-01T00:00:00Z",
        "2026-07-29T10:00:00Z",
        "2100-01-01T00:00:00Z"
      ]

      assert {:ok, out} = Michelson.encode(ty("set", [ty("timestamp")]), values)
      assert Enum.map(expected, &str/1) == out
    end

    test "option: None < Some, Some 0 is not None" do
      type = ty("set", [ty("option", [ty("nat")])])
      assert {:ok, [@none, some(int(0)), some(int(5))]} == Michelson.encode(type, [5, nil, 0])
    end

    test "or: Left < Right, then the value" do
      type = ty("set", [ty("or", [ty("nat"), ty("string")])])
      value = [{:right, "a"}, {:left, 5}, {:left, 1}, {:right, ""}]

      assert {:ok, [left(int(1)), left(int(5)), right(str("")), right(str("a"))]} ==
               Michelson.encode(type, value)
    end

    test "pair: left first, then right" do
      type = ty("set", [ty("pair", [ty("nat"), ty("string")])])
      value = [{2, "a"}, {1, "b"}, {1, "a"}]

      assert {:ok, [pair(int(1), str("a")), pair(int(1), str("b")), pair(int(2), str("a"))]} ==
               Michelson.encode(type, value)
    end

    test "pair nat nat nat: lexicographic on the comb" do
      type = ty("set", [ty("pair", [ty("nat"), ty("nat"), ty("nat")])])
      value = [{1, 2, 3}, {1, 1, 4}, {0, 9, 9}]

      assert {:ok,
              [
                pair(int(0), pair(int(9), int(9))),
                pair(int(1), pair(int(1), int(4))),
                pair(int(1), pair(int(2), int(3)))
              ]} == Michelson.encode(type, value)
    end

    test "map with option keys: None first" do
      type = ty("map", [ty("option", [ty("int")]), ty("nat")])

      assert {:ok, [elt(@none, int(1)), elt(some(int(-3)), int(3)), elt(some(int(5)), int(2))]} ==
               Michelson.encode(type, %{nil => 1, 5 => 2, -3 => 3})
    end
  end

  describe "duplicate keys" do
    test "set of pair nat nat nat: {1, 2, 3} and {1, {2, 3}}" do
      type = ty("set", [ty("pair", [ty("nat"), ty("nat"), ty("nat")])])

      assert {:error, %EncodeError{reason: :duplicate_key, path: [{:key, _}]}} =
               Michelson.encode(type, [{1, 2, 3}, {1, {2, 3}}])
    end

    test "a MapSet holding {1, 2, 3} and {1, {2, 3}}" do
      type = ty("set", [ty("pair", [ty("nat"), ty("nat"), ty("nat")])])

      assert {:error, %EncodeError{reason: :duplicate_key}} =
               Michelson.encode(type, MapSet.new([{1, 2, 3}, {1, {2, 3}}]))
    end

    test "map keys {1, 2, 3} and {1, {2, 3}}" do
      type = ty("map", [ty("pair", [ty("nat"), ty("nat"), ty("nat")]), ty("nat")])

      assert {:error, %EncodeError{reason: :duplicate_key}} =
               Michelson.encode(type, %{{1, 2, 3} => 1, {1, {2, 3}} => 2})
    end

    test "a repeated element in a set list" do
      assert {:error, %EncodeError{reason: :duplicate_key}} =
               Michelson.encode(ty("set", [ty("nat")]), [1, 1])

      assert {:error, %EncodeError{reason: :duplicate_key}} =
               Michelson.encode(ty("set", [ty("unit")]), [:unit, :unit])
    end

    test "edsig and sig with the same bytes" do
      sig = same_bytes(@edsig_a, @edsig, @sig)

      assert {:error, %EncodeError{reason: :duplicate_key}} =
               Michelson.encode(ty("set", [ty("signature")]), [@edsig_a, sig])
    end

    test "spsig1 and sig with the same bytes" do
      sig = same_bytes(@spsig_a, @spsig, @sig)

      assert {:error, %EncodeError{reason: :duplicate_key}} =
               Michelson.encode(ty("set", [ty("signature")]), [sig, @spsig_a])
    end

    test "two DateTimes at the same instant" do
      paris = %DateTime{
        year: 2026,
        month: 7,
        day: 29,
        hour: 12,
        minute: 0,
        second: 0,
        microsecond: {0, 0},
        time_zone: "Europe/Paris",
        zone_abbr: "CEST",
        utc_offset: 3600,
        std_offset: 3600
      }

      assert {:error, %EncodeError{reason: :duplicate_key}} =
               Michelson.encode(ty("set", [ty("timestamp")]), [~U[2026-07-29 10:00:00Z], paris])
    end

    test "option keys {:some, nil} and the same Some None" do
      type = ty("set", [ty("option", [ty("option", [ty("nat")])])])

      assert {:error, %EncodeError{reason: :duplicate_key}} =
               Michelson.encode(type, [{:some, 5}, 5])
    end

    test "or keys given by name and by position" do
      type = ty("set", [ty("or", [ann(ty("nat"), "a"), ty("nat")])])

      assert {:ok, [left(int(1)), right(int(1))]} ==
               Michelson.encode(type, [{:right, 1}, {:a, 1}])

      assert {:error, %EncodeError{reason: :duplicate_key}} =
               Michelson.encode(type, [{:a, 1}, {"a", 1}])
    end
  end

  describe "encode!/2" do
    test "returns the Micheline on success" do
      assert pair(str(@tz1_a), int(5)) ==
               Michelson.encode!(holder_amount(), %{holder: @tz1_a, amount: 5})
    end

    test "raises EncodeError with the path in the message" do
      error =
        assert_raise EncodeError, fn ->
          Michelson.encode!(token_editions(), %{token: %{address: @kt1_a}, editions: 1})
        end

      assert error.reason == :missing_field
      assert error.path == ["token", "token_id"]
      assert Exception.message(error) =~ "token"
      assert Exception.message(error) =~ "token_id"
    end

    test "raises for the ported missing-amount case" do
      type = ty("pair", [ann(ty("nat"), "amount"), ann(ty("nat"), "fee")])

      assert_raise EncodeError, ~r/amount/, fn ->
        Michelson.encode!(type, %{fee: 1})
      end
    end
  end

  describe "schema/1" do
    test "named pair" do
      assert %{"holder" => :address, "amount" => :nat} == Michelson.schema(holder_amount())
    end

    test "or with a unit branch" do
      assert {:or, ["tez", {"fa12", :address}]} == Michelson.schema(tez_or_fa12())
    end

    test "flattened unnamed nested pair" do
      type =
        ty("pair", [
          ann(ty("nat"), "a"),
          ty("pair", [ann(ty("nat"), "b"), ann(ty("nat"), "c")])
        ])

      assert %{"a" => :nat, "b" => :nat, "c" => :nat} == Michelson.schema(type)
    end

    test "named nested pair" do
      assert %{"token" => %{"address" => :address, "token_id" => :nat}, "editions" => :nat} ==
               Michelson.schema(token_editions())
    end

    test "option name on the option or on the inner type" do
      on_option =
        ty("pair", [
          %{"prim" => "option", "annots" => ["%expiry"], "args" => [ty("nat")]},
          ann(ty("nat"), "n")
        ])

      on_inner = ty("pair", [ty("option", [ann(ty("nat"), "expiry")]), ann(ty("nat"), "n")])

      assert %{"expiry" => {:option, :nat}, "n" => :nat} == Michelson.schema(on_option)
      assert %{"expiry" => {:option, :nat}, "n" => :nat} == Michelson.schema(on_inner)
    end

    test "unnamed or" do
      assert {:or, [{:left, :nat}, {:right, :string}]} ==
               Michelson.schema(ty("or", [ty("nat"), ty("string")]))
    end

    test "containers" do
      assert {:option, :nat} == Michelson.schema(ty("option", [ty("nat")]))
      assert {:list, :nat} == Michelson.schema(ty("list", [ty("nat")]))
      assert {:set, :key_hash} == Michelson.schema(ty("set", [ty("key_hash")]))
      assert {:map, :address, :nat} == Michelson.schema(ty("map", [ty("address"), ty("nat")]))

      assert {:big_map, :string, :bytes} ==
               Michelson.schema(ty("big_map", [ty("string"), ty("bytes")]))

      assert {:lambda, :nat, :string} == Michelson.schema(ty("lambda", [ty("nat"), ty("string")]))
      assert {:contract, :unit} == Michelson.schema(ty("contract", [ty("unit")]))
    end

    test "annots that aren't a list are no name" do
      type = ty("pair", [Map.put(ty("nat"), "annots", "%a"), ty("nat")])
      assert {:ok, pair(int(1), int(2))} == Michelson.encode(type, {1, 2})
      assert {:nat, :nat} == Michelson.schema(type)
    end

    test "a malformed type is unsupported instead of raising" do
      assert {:unsupported, %{}} == Michelson.schema(%{})
      assert {:unsupported, []} == Michelson.schema([])

      assert {:or, [{:left, {:unsupported, "x"}}, {:right, :nat}]} ==
               Michelson.schema(ty("or", ["x", ty("nat")]))

      assert {{:unsupported, "x"}, :nat} == Michelson.schema(ty("pair", ["x", ty("nat")]))
    end

    test "containers of named types" do
      type = ty("list", [holder_amount()])
      assert {:list, %{"holder" => :address, "amount" => :nat}} == Michelson.schema(type)
    end
  end

  describe "round trip" do
    test "output survives Forge.forge_micheline/2 and unforge_micheline/2" do
      type =
        ty("pair", [
          ann(ty("address"), "holder"),
          ann(ty("nat"), "amount"),
          ann(ty("option", [ty("int")]), "delta"),
          ann(token_kind(), "currency"),
          ann(ty("map", [ty("string"), ty("bytes")]), "meta"),
          ann(ty("set", [ty("timestamp")]), "times"),
          ann(ty("list", [ty("bool")]), "flags")
        ])

      value = %{
        holder: @kt1_a <> "%transfer",
        amount: 5,
        delta: -42,
        currency: {:fa2, %{address: @kt1_b, token_id: 0}},
        meta: %{"b" => <<0xFF>>, "a" => <<1, 2>>},
        times: [~U[2026-07-29 10:00:00Z], ~U[1970-01-01 00:00:00Z]],
        flags: [true, false]
      }

      assert {:ok, encoded} = Michelson.encode(type, value)

      assert encoded ==
               encoded
               |> Tezex.Forge.forge_micheline(:hex)
               |> Tezex.Forge.unforge_micheline(:hex)
    end
  end

  describe "encoding a contract call" do
    @describetag :tezos

    test "a value for a shadownet FA2 transfer, with the type fetched from the node" do
      rpc = %Tezex.Rpc{endpoint: "https://rpc.shadownet.teztnets.com"}
      {:ok, type} = Tezex.Rpc.entrypoint(rpc, "KT1XsH18aY2GcgSMBAdp2EzHw828iJx2WptU", "transfer")

      value = [
        %{
          from_: "tz1fFtfd49jRi4SmaeWCWMwJbikPSjGf1HKc",
          txs: [%{to_: "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew", token_id: 0, amount: 1}]
        }
      ]

      assert {:ok, micheline} = Michelson.encode(type, value)

      assert micheline == [
               %{
                 "prim" => "Pair",
                 "args" => [
                   %{"string" => "tz1fFtfd49jRi4SmaeWCWMwJbikPSjGf1HKc"},
                   [
                     %{
                       "prim" => "Pair",
                       "args" => [
                         %{"string" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew"},
                         %{"prim" => "Pair", "args" => [%{"int" => "0"}, %{"int" => "1"}]}
                       ]
                     }
                   ]
                 ]
               }
             ]

      # The node accepts it as a value of the entrypoint's type.
      assert {200, _body} = typecheck(micheline, type)
    end
  end

  describe "live node ordering oracle" do
    @describetag :tezos

    test "control: the node rejects an unsorted set" do
      assert {500, body} = typecheck([int(2), int(1)], ty("set", [ty("nat")]))
      assert body =~ "unordered_set_literal"
    end

    test "control: the node orders KT1%abc before KT1 (forged-byte order is rejected)" do
      type = ty("set", [ty("address")])
      assert {500, body} = typecheck([str(@kt1_a), str(@kt1_a <> "%abc")], type)
      assert body =~ "unordered_set_literal"
      assert {200, _} = typecheck([str(@kt1_a <> "%abc"), str(@kt1_a)], type)
    end

    test "control: the node rejects p256 keys in compressed order" do
      {compressed_order, uncompressed_order} = p256_orders()
      type = ty("set", [ty("key")])

      assert {500, body} = typecheck(Enum.map(compressed_order, &str/1), type)
      assert body =~ "unordered_set_literal"
      assert {200, _} = typecheck(Enum.map(uncompressed_order, &str/1), type)
    end

    test "control: the node orders secp256k1 keys by compressed bytes" do
      {compressed_order, uncompressed_order} = secp256k1_orders()
      type = ty("set", [ty("key")])

      assert {200, _} = typecheck(Enum.map(compressed_order, &str/1), type)
      assert {500, body} = typecheck(Enum.map(uncompressed_order, &str/1), type)
      assert body =~ "unordered_set_literal"
    end

    test "control: the node rejects edsig and sig with the same bytes" do
      sig = same_bytes(@edsig_a, @edsig, @sig)
      assert {500, body} = typecheck([str(@edsig_a), str(sig)], ty("set", [ty("signature")]))
      assert body =~ "duplicate"
    end

    test "address set" do
      assert_node_accepts(ty("set", [ty("address")]), Enum.reverse(address_order()))
    end

    test "address map" do
      value = address_order() |> Enum.with_index() |> Map.new()
      assert_node_accepts(ty("map", [ty("address"), ty("nat")]), value)
    end

    test "key set: edpk, sppk, p2pk (compressed and uncompressed orders differ), BLpk" do
      {input, _expected} = key_order()
      assert_node_accepts(ty("set", [ty("key")]), input)
    end

    test "signature set: edsig, spsig1, p2sig, sig, BLsig" do
      {:ok, bls} = BLS.from_seed(<<7::256>>)
      blsig_b = b58(BLS.sign(bls, "michelson"), @blsig)

      {_pub, priv} = :crypto.generate_key(:eddsa, :ed25519, <<9::256>>)
      edsig_c = b58(:crypto.sign(:eddsa, :none, "michelson", [priv, :ed25519]), @edsig)

      values = [
        @edsig_a,
        @edsig_b,
        edsig_c,
        @spsig_a,
        @spsig_b,
        @spsig_c,
        @p2sig_a,
        @p2sig_b,
        @sig_a,
        @blsig_a,
        blsig_b
      ]

      assert_node_accepts(ty("set", [ty("signature")]), values)
    end

    test "key_hash set" do
      values = [
        b58(h20(0xFF), @tz4),
        b58(h20(0x00), @tz1),
        b58(h20(0xFF), @tz1),
        b58(h20(0x00), @tz3),
        b58(h20(0x00), @tz2),
        @tz1_a,
        @tz2_a,
        @tz3_a,
        @tz4_a
      ]

      assert_node_accepts(ty("set", [ty("key_hash")]), values)
    end

    test "chain_id set" do
      values = [
        @chain_id
        | for(raw <- [<<255, 0, 0, 0>>, <<0, 0, 0, 1>>, <<0, 0, 1, 0>>], do: b58(raw, @net))
      ]

      assert_node_accepts(ty("set", [ty("chain_id")]), values)
    end

    test "timestamp set" do
      values = [
        ~U[2100-01-01 00:00:00Z],
        ~U[1970-01-01 00:00:00Z],
        ~U[2026-07-29 10:00:00Z],
        ~U[1969-12-31 23:59:59Z]
      ]

      assert_node_accepts(ty("set", [ty("timestamp")]), values)
    end

    test "string and bytes sets with prefix relations" do
      assert_node_accepts(ty("set", [ty("string")]), ["b", "aa", "a", "", "B", "a\n"])
      assert_node_accepts(ty("set", [ty("bytes")]), [<<2>>, <<1, 0>>, <<1>>, <<>>, <<1, 255>>])
    end

    test "int, nat, mutez, bool, unit sets" do
      assert_node_accepts(ty("set", [ty("int")]), [
        2 ** 64,
        -(2 ** 64),
        0,
        -1,
        1,
        2 ** 53 + 1,
        2 ** 53
      ])

      assert_node_accepts(ty("set", [ty("nat")]), [1, 256, 129])
      assert_node_accepts(ty("set", [ty("mutez")]), [10, 2 ** 63 - 1, 0])
      assert_node_accepts(ty("set", [ty("bool")]), [true, false])
      assert_node_accepts(ty("set", [ty("unit")]), [:unit])
    end

    test "option, or and pair keys" do
      assert_node_accepts(ty("set", [ty("option", [ty("address")])]), [
        @tz1_a,
        nil,
        @kt1_a,
        @kt1_a <> "%abc"
      ])

      assert_node_accepts(
        ty("set", [ty("or", [ty("key_hash"), ty("int")])]),
        [{:right, 5}, {:left, @tz2_a}, {:right, -5}, {:left, @tz1_a}]
      )

      assert_node_accepts(
        ty("set", [ty("pair", [ty("address"), ty("or", [ty("nat"), ty("string")])])]),
        [
          {@kt1_a, {:left, 1}},
          {@tz1_a, {:right, "a"}},
          {@tz1_a, {:left, 2}},
          {@kt1_a <> "%abc", {:left, 0}}
        ]
      )

      assert_node_accepts(
        ty("map", [
          ty("pair", [ty("option", [ty("nat")]), ty("or", [ty("string"), ty("bytes")])]),
          ty("nat")
        ]),
        %{
          {5, {:right, <<1>>}} => 1,
          {nil, {:left, "b"}} => 2,
          {0, {:left, "a"}} => 3,
          {nil, {:right, <<>>}} => 4,
          {5, {:left, "z"}} => 5
        }
      )
    end

    test "pair nat nat nat keys" do
      assert_node_accepts(
        ty("set", [ty("pair", [ty("nat"), ty("nat"), ty("nat")])]),
        [{1, 2, 3}, {1, 1, 4}, {0, 9, 9}, {1, {1, 3}}]
      )
    end
  end

  # Types

  defp ty(prim), do: %{"prim" => prim}
  defp ty(prim, args), do: %{"prim" => prim, "args" => args}
  defp ann(type, name), do: Map.put(type, "annots", ["%" <> name])
  defp tez_or_fa12, do: ty("or", [ann(ty("unit"), "tez"), ann(ty("address"), "fa12")])
  defp holder_amount, do: ty("pair", [ann(ty("address"), "holder"), ann(ty("nat"), "amount")])

  defp token_editions do
    ty("pair", [
      ann(ty("pair", [ann(ty("address"), "address"), ann(ty("nat"), "token_id")]), "token"),
      ann(ty("nat"), "editions")
    ])
  end

  defp token_kind do
    ty("or", [
      ann(ty("unit"), "tez"),
      ty("or", [
        ann(ty("address"), "fa12"),
        ann(ty("pair", [ann(ty("address"), "address"), ann(ty("nat"), "token_id")]), "fa2")
      ])
    ])
  end

  # Micheline values

  defp int(n), do: %{"int" => Integer.to_string(n)}
  defp str(s), do: %{"string" => s}
  defp hex(b), do: %{"bytes" => Base.encode16(b, case: :lower)}
  defp pair(a, b), do: %{"prim" => "Pair", "args" => [a, b]}
  defp left(v), do: %{"prim" => "Left", "args" => [v]}
  defp right(v), do: %{"prim" => "Right", "args" => [v]}
  defp some(v), do: %{"prim" => "Some", "args" => [v]}
  defp elt(k, v), do: %{"prim" => "Elt", "args" => [k, v]}

  # Assertions

  defp assert_error(type, value, reason, path) do
    assert {:error, %EncodeError{reason: ^reason, path: ^path}} = Michelson.encode(type, value)
  end

  defp assert_set_order(elem_type, input, expected, to_micheline) do
    assert {:ok, out} = Michelson.encode(ty("set", [elem_type]), input)
    assert Enum.map(expected, to_micheline) == out
  end

  defp assert_node_accepts(type, value) do
    assert {:ok, encoded} = Michelson.encode(type, value)
    {status, body} = typecheck(encoded, type)
    assert status == 200, "node rejected #{inspect(encoded)}: #{body}"
  end

  defp typecheck(data, type) do
    body = Jason.encode!(%{"data" => data, "type" => type})

    {:ok, %Finch.Response{status: status, body: resp}} =
      :post
      |> Finch.build(@typecheck_url, [{"content-type", "application/json"}], body)
      |> Finch.request(Tezex.Finch, receive_timeout: 30_000)

    {status, resp}
  end

  # Base58 values

  defp b58(payload, prefix), do: Base58Check.encode(payload, prefix)
  defp h20(byte), do: :binary.copy(<<byte>>, 20)
  defp sr1(hash), do: b58(hash, @sr1)

  defp payload_of(encoded, prefix) do
    {:ok, decoded} = Base58Check.decode58(encoded)
    size = byte_size(decoded) - byte_size(prefix) - 4
    <<^prefix::binary, payload::binary-size(^size), _::binary-size(4)>> = decoded
    payload
  end

  defp same_bytes(encoded, from_prefix, to_prefix),
    do: encoded |> payload_of(from_prefix) |> b58(to_prefix)

  defp break_checksum(encoded) do
    last = String.last(encoded)
    replacement = if last == "1", do: "2", else: "1"
    String.slice(encoded, 0..-2//1) <> replacement
  end

  # Expected orders, derived from the spec rules (todo.md "Facts checked against Octez").

  defp address_order do
    kt_a = b58(h20(0x10), @kt1)
    kt_b = b58(h20(0x20), @kt1)

    [
      b58(h20(0x00), @tz1),
      b58(h20(0xFF), @tz1),
      b58(h20(0x00), @tz2),
      b58(h20(0x00), @tz3),
      b58(h20(0x00), @tz4),
      kt_a <> "%abc",
      kt_a <> "%defaul",
      kt_a,
      kt_a <> "%default_x",
      kt_a <> "%zzz",
      kt_b <> "%abc",
      kt_b,
      sr1(h20(0x00))
    ]
  end

  # {input, expected}: curve first, then bytes; p256 by uncompressed x‖y.
  defp key_order do
    ed = for i <- 1..3, do: ed25519_key(i)
    {sp_compressed, _sp_uncompressed} = secp256k1_orders()
    {_p2_compressed, p2_uncompressed} = p256_orders()
    bl = for i <- 1..2, do: bls_key(i)

    expected = sort_by_first(ed) ++ sp_compressed ++ p2_uncompressed ++ sort_by_first(bl)

    input =
      Enum.reverse(Enum.map(bl, &elem(&1, 1))) ++
        Enum.reverse(p2_uncompressed) ++
        Enum.reverse(sp_compressed) ++
        Enum.map(ed, &elem(&1, 1))

    {input, expected}
  end

  defp secp256k1_orders, do: ecdsa_orders(:secp256k1, 1..12, @sppk)

  defp p256_orders, do: ecdsa_orders(:secp256r1, [1, 2, 3, 4, 10], @p2pk)

  # Keys in compressed order and in uncompressed order; the two must differ,
  # or the keys can't tell the two rules apart.
  defp ecdsa_orders(curve, indices, prefix) do
    keys = for i <- indices, do: ecdsa_key(curve, i, prefix)
    compressed = keys |> Enum.sort_by(&elem(&1, 0)) |> Enum.map(&elem(&1, 2))
    uncompressed = keys |> Enum.sort_by(&elem(&1, 1)) |> Enum.map(&elem(&1, 2))
    assert compressed != uncompressed
    {compressed, uncompressed}
  end

  defp sort_by_first(pairs), do: pairs |> Enum.sort_by(&elem(&1, 0)) |> Enum.map(&elem(&1, 1))

  defp ed25519_key(i) do
    {pub, _priv} = :crypto.generate_key(:eddsa, :ed25519, <<i::256>>)
    {pub, b58(pub, @edpk)}
  end

  defp ecdsa_key(curve, i, prefix) do
    {<<4, x::binary-size(32), y::binary-size(32)>>, _} =
      :crypto.generate_key(:ecdh, curve, <<i::256>>)

    <<_::255, parity::1>> = y
    compressed = <<2 + parity, x::binary>>
    {compressed, x <> y, b58(compressed, prefix)}
  end

  defp bls_key(i) do
    {:ok, key} = BLS.from_seed(<<i::256>>)
    pub = BLS.get_public_key(key)
    {pub, b58(pub, @blpk)}
  end
end
