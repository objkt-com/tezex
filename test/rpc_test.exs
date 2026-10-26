defmodule Tezex.RpcTest do
  use ExUnit.Case, async: true

  alias Tezex.OperationResultFixture
  alias Tezex.Rpc
  alias Tezex.Rpc.EntrypointCache
  alias Tezex.TransactionFixture
  doctest Tezex.Rpc, import: true

  @endpoint "https://ghostnet.ecadinfra.com"
  @ghostnet_rpc %Rpc{endpoint: @endpoint}
  @ghostnet_1_address "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew"
  @ghostnet_1_pkey "edsk33h91RysSBUiYyEWbeRwo41YeZrtMPTNsuZ9nzsYWwiV8CFyKi"
  @ghostnet_2_address "tz1cMcDFLgFe2picQbo4DY1i6mZJiVhPCu5B"
  @branch "BLWdshvgEYbtUaABnmqkMuyMezpfsu36DEJPDJN63CW3TFuk7bP"

  @shadownet_endpoint "https://rpc.shadownet.teztnets.com"
  @shadownet_rpc %Rpc{endpoint: @shadownet_endpoint}
  # FA2 token contract on shadownet, with named entrypoints and no %default.
  @shadownet_fa2 "KT1XsH18aY2GcgSMBAdp2EzHw828iJx2WptU"
  @shadownet_fa2_entrypoints ~w(balance_of mint set_administrator set_metadata set_pause transfer update_operators)
  @shadownet_implicit "tz1fFtfd49jRi4SmaeWCWMwJbikPSjGf1HKc"
  # Valid KT1 checksum over 20 zero bytes, never originated.
  @missing_contract "KT18amZmM5W7qDWVt2pH6uj7sCEd3kbzLrHT"

  @tag :tezos
  test "get_counter_for_account" do
    assert {:ok, counter} =
             Rpc.get_counter_for_account(@ghostnet_rpc, "tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z")

    assert is_integer(counter)
  end

  test "prepare_operation/4" do
    contents = [
      %{"amount" => "100", "destination" => @ghostnet_2_address, "kind" => "transaction"}
    ]

    assert %{
             "branch" => @branch,
             "contents" => [
               %{
                 "amount" => "100",
                 "counter" => "1123",
                 "destination" => "tz1cMcDFLgFe2picQbo4DY1i6mZJiVhPCu5B",
                 "fee" => "0",
                 "gas_limit" => "3040",
                 "kind" => "transaction",
                 "source" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
                 "storage_limit" => "257"
               }
             ]
           } == Rpc.prepare_operation(contents, @ghostnet_1_address, 1123, @branch)
  end

  test "forge_and_sign_operation/2" do
    operation = %{
      "branch" => @branch,
      "contents" => [
        %{
          "amount" => "100",
          "counter" => "1123",
          "destination" => "tz1cMcDFLgFe2picQbo4DY1i6mZJiVhPCu5B",
          "fee" => "0",
          "gas_limit" => "1451",
          "kind" => "transaction",
          "source" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
          "storage_limit" => "257"
        }
      ]
    }

    result =
      "6940b2318870c4b84862aef187c1bbcd4138170459e85092fe34be5d179f40ac6c00980d7cebb50d4b83a4e3307b3ca1b40ebe8f71ab00e308ab0b8102640000b75f0c30536bee108b068d90b151ce846aca11b1009bc207291f08c7117ea3a341328a036ce7bd5da996d9148cc491f96c3097748d7adcdb60599504ae5227aea4a6e69d536baaf96ae2bbb6c261a69d000b323f0a"

    assert {:ok, result} == Rpc.forge_and_sign_operation(operation, @ghostnet_1_pkey)
  end

  test "forge_and_sign_operation/2 propagates a missing-keys error" do
    assert {:error, {:missing_keys, ["branch"]}} =
             Rpc.forge_and_sign_operation(%{"contents" => []}, @ghostnet_1_pkey)
  end

  describe "fill_operation_fee/3" do
    test "a contract operation" do
      assert {:ok,
              %{
                "contents" => [
                  %{
                    "amount" => "1000000",
                    "counter" => "26949360",
                    "destination" => "KT1MFWsAXGUZ4gFkQnjByWjrrVtuQi4Tya8G",
                    "fee" => "651",
                    "gas_limit" => "2419",
                    "kind" => "transaction",
                    "source" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
                    "storage_limit" => "289"
                  }
                ]
              }} = Rpc.fill_operation_fee(%{"contents" => []}, OperationResultFixture.offer())
    end

    test "a transfer" do
      assert {:ok,
              %{
                "contents" => [
                  %{
                    "amount" => "100",
                    "fee" => "285",
                    "gas_limit" => "269",
                    "storage_limit" => "100"
                  }
                ]
              }} = Rpc.fill_operation_fee(%{"contents" => []}, OperationResultFixture.transfer())
    end

    test "a settle_auction" do
      assert {:ok,
              %{
                "contents" => [
                  %{"fee" => "2372", "gas_limit" => "20847", "storage_limit" => "103"}
                ]
              }} =
               Rpc.fill_operation_fee(
                 %{"contents" => []},
                 OperationResultFixture.settle_auction()
               )
    end

    test "propagates a missing-keys error" do
      [content] = OperationResultFixture.transfer()
      invalid = [Map.delete(content, "amount")]

      assert {:error, {:missing_keys, ["amount"]}} =
               Rpc.fill_operation_fee(%{"contents" => []}, invalid)
    end

    test "handles a non-origination/transaction operation kind" do
      preapplied = [
        %{
          "kind" => "delegation",
          "source" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
          "fee" => "0",
          "counter" => "1",
          "gas_limit" => "1000",
          "storage_limit" => "0",
          "delegate" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
          "metadata" => %{
            "operation_result" => %{"consumed_milligas" => "1000000", "status" => "applied"}
          }
        }
      ]

      assert {:ok, %{"contents" => [%{"kind" => "delegation", "fee" => fee}]}} =
               Rpc.fill_operation_fee(%{"contents" => []}, preapplied)

      assert is_binary(fee)
    end
  end

  describe "preapply_errors/1" do
    test "collects internal operation errors when some results carry none" do
      error = %{"id" => "proto.023.michelson_v1.script_rejected", "kind" => "temporary"}

      preapplied_operations = [
        backtracked([
          %{"result" => %{"status" => "applied"}},
          %{"result" => %{"status" => "failed", "errors" => [error]}}
        ])
      ]

      assert [^error] = Rpc.preapply_errors(preapplied_operations)
    end

    test "collects internal operation errors across several operations" do
      error_a = %{"id" => "proto.023.michelson_v1.script_rejected", "kind" => "temporary"}
      error_b = %{"id" => "proto.023.contract.balance_too_low", "kind" => "temporary"}

      preapplied_operations = [
        backtracked([%{"result" => %{"status" => "failed", "errors" => [error_a]}}]),
        backtracked([%{"result" => %{"status" => "failed", "errors" => [error_b]}}])
      ]

      assert [^error_a, ^error_b] = Rpc.preapply_errors(preapplied_operations)
    end

    test "falls back to the operation result errors" do
      error = %{"id" => "proto.023.contract.balance_too_low", "kind" => "temporary"}

      preapplied_operations = [
        %{
          "kind" => "transaction",
          "metadata" => %{"operation_result" => %{"status" => "failed", "errors" => [error]}}
        }
      ]

      assert [[^error]] = Rpc.preapply_errors(preapplied_operations)
    end
  end

  describe "send_operation/4" do
    @describetag :tezos

    setup do
      # Wait approximatively one block between each transaction
      Process.sleep(:timer.seconds(10))
    end

    test "a contract operation" do
      contents = TransactionFixture.offer(@ghostnet_1_address)

      assert {:ok, operation_id} =
               Rpc.send_operation(@ghostnet_rpc, contents, @ghostnet_1_address, @ghostnet_1_pkey)

      assert is_binary(operation_id)
    end

    test "a transfer" do
      contents = TransactionFixture.offer(@ghostnet_2_address)

      assert {:ok, operation_id} =
               Rpc.send_operation(@ghostnet_rpc, contents, @ghostnet_1_address, @ghostnet_1_pkey)

      assert is_binary(operation_id)
    end
  end

  @tag :tezos
  test "return preapply errors" do
    contents = [
      %{"amount" => "1000000000", "destination" => @ghostnet_2_address, "kind" => "transaction"}
    ]

    assert {:error,
            {:preapply_failed,
             [
               [
                 %{
                   "amount" => "1000000000",
                   "balance" => _,
                   "contract" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
                   "id" => error_a,
                   "kind" => "temporary"
                 },
                 %{"amounts" => [_, "1000000000"], "id" => error_b, "kind" => "temporary"}
               ]
             ]}} =
             Rpc.send_operation(@ghostnet_rpc, contents, @ghostnet_1_address, @ghostnet_1_pkey)

    assert String.ends_with?(error_a, "balance_too_low"), error_a
    assert String.ends_with?(error_b, "subtraction_underflow"), error_b
  end

  describe "entrypoints/2 and entrypoint/3" do
    @describetag :tezos

    test "entrypoints/2 lists the named entrypoints" do
      assert {:ok, %{"entrypoints" => entrypoints} = body} =
               Rpc.entrypoints(@shadownet_rpc, @shadownet_fa2)

      assert Enum.sort(Map.keys(entrypoints)) == @shadownet_fa2_entrypoints
      assert entrypoints["set_pause"] == %{"prim" => "bool"}
      refute Map.has_key?(body, "unreachable")
      assert {:ok, ^body} = EntrypointCache.lookup({@shadownet_endpoint, "main", @shadownet_fa2})
    end

    test "entrypoint/3 returns the type of a named entrypoint" do
      key = {@shadownet_endpoint, "main", @shadownet_fa2, "set_pause"}

      assert {:ok, %{"prim" => "bool"}} =
               Rpc.entrypoint(@shadownet_rpc, @shadownet_fa2, "set_pause")

      assert {:ok, %{"prim" => "bool"}} = EntrypointCache.lookup(key)
    end

    test "entrypoint/3 returns the whole parameter type for default without %default" do
      assert {:ok, %{"prim" => "or"} = type} =
               Rpc.entrypoint(@shadownet_rpc, @shadownet_fa2, "default")

      assert Enum.sort(or_leaf_names(type)) == @shadownet_fa2_entrypoints
    end

    test "entrypoint/3 returns no_such_entrypoint for an unknown name" do
      key = {@shadownet_endpoint, "main", @shadownet_fa2, "nope"}

      assert {:error, {:no_such_entrypoint, "nope"}} =
               Rpc.entrypoint(@shadownet_rpc, @shadownet_fa2, "nope")

      assert :error = EntrypointCache.lookup(key)
    end

    test "entrypoint/3 URI-encodes the name" do
      assert {:error, {:no_such_entrypoint, "a b/c"}} =
               Rpc.entrypoint(@shadownet_rpc, @shadownet_fa2, "a b/c")
    end

    test "entrypoint/3 returns no_such_entrypoint for an implicit account" do
      assert {:error, {:no_such_entrypoint, "default"}} =
               Rpc.entrypoint(@shadownet_rpc, @shadownet_implicit, "default")
    end

    test "entrypoint/3 returns no_such_entrypoint for a contract that doesn't exist" do
      assert {:error, {:no_such_entrypoint, "transfer"}} =
               Rpc.entrypoint(@shadownet_rpc, @missing_contract, "transfer")
    end

    test "entrypoints/2 returns a 404 for an implicit account and a missing contract" do
      for address <- [@shadownet_implicit, @missing_contract] do
        assert {:error, {:http_status, %Finch.Response{status: 404}}} =
                 Rpc.entrypoints(@shadownet_rpc, address)
      end
    end
  end

  describe "entrypoint cache" do
    # Nothing listens on port 1, so any request that reaches the network fails.
    # The path makes each test's endpoint, and so its cache keys, unique.
    setup do
      %{endpoint: "http://127.0.0.1:1/#{System.unique_integer([:positive])}"}
    end

    test "entrypoints/2 serves a cached list without a request", %{endpoint: endpoint} do
      body = %{"entrypoints" => %{"set_pause" => %{"prim" => "bool"}}}
      :ok = EntrypointCache.put({endpoint, "main", @shadownet_fa2}, body)
      assert {:ok, ^body} = Rpc.entrypoints(%Rpc{endpoint: endpoint}, @shadownet_fa2)
    end

    test "entrypoint/3 serves a cached type without a request", %{endpoint: endpoint} do
      type = %{"prim" => "bool"}
      :ok = EntrypointCache.put({endpoint, "main", @shadownet_fa2, "set_pause"}, type)
      assert {:ok, ^type} = Rpc.entrypoint(%Rpc{endpoint: endpoint}, @shadownet_fa2, "set_pause")
    end

    test "errors are not cached", %{endpoint: endpoint} do
      rpc = %Rpc{endpoint: endpoint}

      assert {:error, {:transport, _}} = Rpc.entrypoint(rpc, @shadownet_fa2, "transfer")
      assert {:error, {:transport, _}} = Rpc.entrypoints(rpc, @shadownet_fa2)
      assert :error = EntrypointCache.lookup({endpoint, "main", @shadownet_fa2, "transfer"})
      assert :error = EntrypointCache.lookup({endpoint, "main", @shadownet_fa2})
    end

    test "keys separate endpoints and chains", %{endpoint: endpoint} do
      :ok =
        EntrypointCache.put({endpoint, "main", @shadownet_fa2, "set_pause"}, %{"prim" => "bool"})

      for rpc <- [%Rpc{endpoint: endpoint <> "x"}, %Rpc{endpoint: endpoint, chain_id: "other"}] do
        assert {:error, {:transport, _}} = Rpc.entrypoint(rpc, @shadownet_fa2, "set_pause")
      end
    end

    test "fetch/2 stores successes only", %{endpoint: endpoint} do
      key = {endpoint, "main", @shadownet_fa2, "x"}

      assert {:error, :boom} = EntrypointCache.fetch(key, fn -> {:error, :boom} end)
      assert :error = EntrypointCache.lookup(key)
      assert {:ok, 1} = EntrypointCache.fetch(key, fn -> {:ok, 1} end)
      assert {:ok, 1} = EntrypointCache.fetch(key, fn -> flunk("cache miss") end)
    end

    test "clear/0 removes every entry", %{endpoint: endpoint} do
      key = {endpoint, "main", @shadownet_fa2}
      :ok = EntrypointCache.put(key, %{})
      :ok = EntrypointCache.clear()
      assert :error = EntrypointCache.lookup(key)
    end
  end

  defp backtracked(internal_operation_results) do
    %{
      "kind" => "transaction",
      "metadata" => %{
        "operation_result" => %{"status" => "backtracked"},
        "internal_operation_results" => internal_operation_results
      }
    }
  end

  # Entrypoint names of the leaves reached through unannotated `or` nodes.
  defp or_leaf_names(%{"prim" => "or", "args" => [left, right]} = node)
       when not is_map_key(node, "annots") do
    or_leaf_names(left) ++ or_leaf_names(right)
  end

  defp or_leaf_names(%{"annots" => annots}) do
    for "%" <> name <- annots, do: name
  end
end
