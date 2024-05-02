defmodule Tezex.RpcTest do
  use ExUnit.Case, async: true

  alias Tezex.Rpc
  doctest Tezex.Rpc

  @endpoint "https://ghostnet.tezos.marigold.dev/"

  test "get_counter_for_account" do
    counter =
      Rpc.get_counter_for_account(
        %Rpc{endpoint: @endpoint},
        "tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z"
      )

    assert is_integer(counter)
  end

  test "build_contract_operation" do
    rpc = %Rpc{endpoint: @endpoint}
    public_key_hash = "tz1b9kV41KV9N3sp69ycLdSoZ2Ak8jXwtNPv"
    encoded_private_key = "edsk4TjJWEszkHKono7XMnepVqwi37FrpbVt1KCsifJeAGimxheShG"
    counter = Rpc.get_next_counter_for_account(rpc, public_key_hash)

    contract = "KT1MFWsAXGUZ4gFkQnjByWjrrVtuQi4Tya8G"
    entrypoint = "offer"
    gas_limit = 1000
    storage_limit = 1000
    fee = 1000
    amount = 1

    price = 100
    fa_contract = "KT1JzqDsR2eMqhu76uRqAUEuTWj7bbwqa9wY"
    token_id = "5"
    royalty_address = public_key_hash
    royalty_share = 1000

    parameters = %{
      prim: "Pair",
      args: [
        %{
          prim: "Pair",
          args: [%{string: fa_contract}, %{prim: "Some", args: [%{int: token_id}]}]
        },
        %{
          prim: "Pair",
          args: [
            %{prim: "Right", args: [%{prim: "Right", args: [%{prim: "Unit"}]}]},
            %{
              prim: "Pair",
              args: [
                %{int: Integer.to_string(price)},
                %{
                  prim: "Pair",
                  args: [
                    [
                      %{
                        prim: "Elt",
                        args: [
                          %{string: royalty_address},
                          %{int: Integer.to_string(royalty_share)}
                        ]
                      }
                    ],
                    %{
                      prim: "Pair",
                      args: [
                        %{prim: "None"},
                        %{
                          prim: "Pair",
                          args: [[], %{prim: "Pair", args: [%{prim: "None"}, %{prim: "None"}]}]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }

    tx =
      Rpc.build_contract_operation(
        rpc,
        public_key_hash,
        counter,
        contract,
        amount,
        fee,
        storage_limit,
        gas_limit,
        entrypoint,
        parameters,
        encoded_private_key
      )
  end
end
