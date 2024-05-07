defmodule Tezex.TezexTest do
  use ExUnit.Case, async: false

  alias Tezex.ForgeOperation
  alias Tezex.Rpc
  alias Tezex.Crypto

  doctest Tezex.Rpc

  @wallet_address "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew"
  @wallet_private_key "edsk33h91RysSBUiYyEWbeRwo41YeZrtMPTNsuZ9nzsYWwiV8CFyKi"

  @endpoint "https://ghostnet.tezos.marigold.dev/"

  @tag :tezos
  test "inject an operation" do
    rpc = %Rpc{endpoint: @endpoint}

    {:ok, block_head} = Rpc.get_block_at_offset(rpc, 0)
    branch = binary_part(block_head["hash"], 0, 51)

    counter = Rpc.get_next_counter_for_account(rpc, @wallet_address)

    operation = %{
      "branch" => branch,
      "contents" => [
        %{
          "amount" => "100",
          "counter" => Integer.to_string(counter),
          "destination" => "tz1cMcDFLgFe2picQbo4DY1i6mZJiVhPCu5B",
          "fee" => "349",
          "gas_limit" => "186",
          "kind" => "transaction",
          "source" => @wallet_address,
          "storage_limit" => "0"
        }
      ]
    }

    forged_operation = ForgeOperation.operation_group(operation)

    signature = Crypto.sign_operation(@wallet_private_key, forged_operation)
    {:ok, decoded_signature} = Crypto.decode_signature(signature)

    decoded_signature = Base.encode16(decoded_signature, case: :lower)

    assert {:ok, operation_id} = Rpc.inject_operation(rpc, forged_operation, decoded_signature)
  end
end
