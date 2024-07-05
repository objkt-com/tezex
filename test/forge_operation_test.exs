defmodule Tezex.ForgeOperationTest do
  use ExUnit.Case, async: true

  alias Tezex.ForgeOperation

  describe "Tezos P2P message encoder test suite" do
    test "correctly encode some transactions" do
      transaction = %{
        "kind" => "transaction",
        "source" => "tz1VJAdH2HRUZWfohXW59NPYQKFMe1csroaX",
        "fee" => "10000",
        "counter" => "9",
        "storage_limit" => "10001",
        "gas_limit" => "10002",
        "amount" => "10000000",
        "destination" => "tz2G4TwEbsdFrJmApAxJ1vdQGmADnBp95n9m"
      }

      {:ok, result} = ForgeOperation.transaction(transaction)

      assert Base.encode16(result, case: :lower) ==
               "6c0069ef8fb5d47d8a4321c94576a2316a632be8ce89904e09924e914e80ade204000154f5d8f71ce18f9f05bb885a4120e64c667bc1b400"

      transaction = %{
        "destination" => "KT1X1rMCkifsoDJ1ynsHFqdvyagJKc9J6wEq",
        "amount" => "10000",
        "storage_limit" => "0",
        "gas_limit" => "11697",
        "counter" => "29892",
        "fee" => "100000",
        "source" => "tz1b2icJC4E7Y2ED1xsZXuqYpF7cxHDtduuP",
        "kind" => "transaction",
        "parameters" => %{"entrypoint" => "default", "value" => %{"prim" => "Unit"}}
      }

      {:ok, result} = ForgeOperation.transaction(transaction)

      assert Base.encode16(result, case: :lower) ==
               "6c00a8d45bdc966ddaaac83188a1e1c1fde2a3e05e5ca08d06c4e901b15b00904e01f61128c6abd2426d0c49b1fee1fa8c98dcc4ce0a0000"
    end

    test "Dexter 2021Q1 tests" do
      transaction = %{
        "kind" => "transaction",
        "amount" => "100000000",
        "destination" => "KT1XTUGj7Rkgh6vLVDu91h81Xu2WGfyTxpqi",
        "parameters" => %{
          "entrypoint" => "xtzToToken",
          "value" => %{
            "prim" => "Pair",
            "args" => [
              %{"string" => "tz1RhnGx9hCxbrN8zKEKLbwU1zKLYZTqRs63"},
              %{
                "prim" => "Pair",
                "args" => [
                  %{"int" => "198180477354428686667"},
                  %{"string" => "2021-01-21T18:09:14.519Z"}
                ]
              }
            ]
          }
        },
        "storage_limit" => "0",
        "gas_limit" => "11697",
        "counter" => "29892",
        "fee" => "100000",
        "source" => "tz1RUGhq8sQpfGu1W2kf7MixqWX7oxThBFLr"
      }

      {:ok, result} = ForgeOperation.transaction(transaction)

      assert Base.encode16(result, case: :lower) ==
               "6c003ff84abc64319bda01968fd5269981d7615a6f75a08d06c4e901b15b0080c2d72f01fae98b912bb3644d56b8409cb98f40c779a9befe00ffff0a78747a546f546f6b656e0000005507070100000024747a3152686e47783968437862724e387a4b454b4c627755317a4b4c595a5471527336330707008b858b81c289bfcefc2a0100000018323032312d30312d32315431383a30393a31342e3531395a"
    end

    test "correctly encode a reveal operation" do
      reveal = %{
        "kind" => "reveal",
        "source" => "tz1VJAdH2HRUZWfohXW59NPYQKFMe1csroaX",
        "fee" => "0",
        "counter" => "425748",
        "storage_limit" => "0",
        "gas_limit" => "10000",
        "public_key" => "edpkuDuXgPVJi3YK2GKL6avAK3GyjqyvpJjG9gTY5r2y72R7Teo65i"
      }

      {:ok, result} = ForgeOperation.reveal(reveal)

      assert Base.encode16(result, case: :lower) ==
               "6b0069ef8fb5d47d8a4321c94576a2316a632be8ce890094fe19904e00004c7b0501f6ea08f472b7e88791d3b8da49d64ac1e2c90f93c27e6531473305c6"
    end

    test "correctly encode a contract origination operation" do
      origination = %{
        "kind" => "origination",
        "source" => "tz1VJAdH2HRUZWfohXW59NPYQKFMe1csroaX",
        "fee" => "10000",
        "counter" => "9",
        "storage_limit" => "10001",
        "gas_limit" => "10002",
        "balance" => "10003",
        "script" => %{
          "code" => [
            %{"prim" => "parameter", "args" => [%{"prim" => "int"}]},
            %{"prim" => "storage", "args" => [%{"prim" => "int"}]},
            %{
              "prim" => "code",
              "args" => [
                [
                  %{"prim" => "CAR"},
                  %{"prim" => "PUSH", "args" => [%{"prim" => "int"}, %{"int" => "1"}]},
                  %{"prim" => "ADD"},
                  %{
                    "prim" => "PUSH",
                    "args" => [%{"prim" => "bytes"}, %{"bytes" => "0123456789abcdef"}]
                  },
                  %{"prim" => "DROP"},
                  %{"prim" => "NIL", "args" => [%{"prim" => "operation"}]},
                  %{"prim" => "PAIR"}
                ]
              ]
            }
          ],
          "storage" => %{"int" => "30"}
        }
      }

      assert ForgeOperation.operation(Map.drop(origination, ["storage_limit"])) ==
               {:error, "Operation content is missing required keys: storage_limit"}

      {:ok, result} = ForgeOperation.operation(origination)

      assert Base.encode16(result, case: :lower) ==
               "6d0069ef8fb5d47d8a4321c94576a2316a632be8ce89904e09924e914e934e000000003702000000320500035b0501035b0502020000002303160743035b00010312074303690a000000080123456789abcdef0320053d036d034200000002001e"
    end

    test "correctly encode a contract origination operation 2" do
      origination = %{
        "kind" => "origination",
        "source" => "tz1VJAdH2HRUZWfohXW59NPYQKFMe1csroaX",
        "delegate" => "tz1MRXFvJdkZdsr4CpGNB9dwA37LvMoNf7pM",
        "fee" => "10000",
        "counter" => "9",
        "storage_limit" => "10001",
        "gas_limit" => "10002",
        "balance" => "10003",
        "script" => %{
          "code" => [
            %{"prim" => "parameter", "args" => [%{"prim" => "int"}]},
            %{"prim" => "storage", "args" => [%{"prim" => "int"}]},
            %{
              "prim" => "code",
              "args" => [
                [
                  %{"prim" => "CAR"},
                  %{"prim" => "PUSH", "args" => [%{"prim" => "int"}, %{"int" => "1"}]},
                  %{"prim" => "ADD"},
                  %{
                    "prim" => "PUSH",
                    "args" => [%{"prim" => "bytes"}, %{"bytes" => "0123456789abcdef"}]
                  },
                  %{"prim" => "DROP"},
                  %{"prim" => "NIL", "args" => [%{"prim" => "operation"}]},
                  %{"prim" => "PAIR"}
                ]
              ]
            }
          ],
          "storage" => %{"int" => "30"}
        }
      }

      {:ok, result} = ForgeOperation.operation(origination)

      assert Base.encode16(result, case: :lower) ==
               "6d0069ef8fb5d47d8a4321c94576a2316a632be8ce89904e09924e914e934eff001392b07a567de5cb3a4301fbef2030696b4dfd8b0000003702000000320500035b0501035b0502020000002303160743035b00010312074303690a000000080123456789abcdef0320053d036d034200000002001e"
    end

    test "correctly encode a delegation operation" do
      delegation = %{
        "kind" => "delegation",
        "source" => "tz1VJAdH2HRUZWfohXW59NPYQKFMe1csroaX",
        "fee" => "10000",
        "counter" => "9",
        "storage_limit" => "10001",
        "gas_limit" => "10002",
        "delegate" => "tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5"
      }

      {:ok, result} = ForgeOperation.delegation(delegation)

      assert Base.encode16(result, case: :lower) ==
               "6e0069ef8fb5d47d8a4321c94576a2316a632be8ce89904e09924e914eff026fde46af0356a0476dae4e4600172dc9309b3aa4"

      delegation = %{delegation | "delegate" => nil}

      {:ok, result} = ForgeOperation.delegation(delegation)

      assert Base.encode16(result, case: :lower) ==
               "6e0069ef8fb5d47d8a4321c94576a2316a632be8ce89904e09924e914e00"
    end

    test "correctly encode an activation operation" do
      activation = %{
        "kind" => "activate_account",
        "pkh" => "tz1LoKbFyYHTkCnj9mgRKFb9g8pP4Lr3zniP",
        "secret" => "9b7f631e52f877a1d363474404da8130b0b940ee"
      }

      {:ok, result} = ForgeOperation.activate_account(activation)

      assert Base.encode16(result, case: :lower) ==
               "040cb9f9da085607c05cac1ca4c62a3f3cfb8146aa9b7f631e52f877a1d363474404da8130b0b940ee"
    end
  end

  test "validate_required_keys/2" do
    assert ForgeOperation.validate_required_keys(%{"a" => 1, "b" => 2}, ~w(a b)) == :ok

    assert ForgeOperation.validate_required_keys(%{"a" => 1, "b" => 2}, ~w(a b c)) ==
             {:error, "Operation content is missing required keys: c"}

    assert ForgeOperation.validate_required_keys(
             %{"a" => %{"b" => 2, "c" => %{"d" => 3}}},
             ~w(a a.b a.c a.c.d)
           ) == :ok

    assert ForgeOperation.validate_required_keys(
             %{"a" => %{"b" => 2, "c" => %{}}},
             ~w(a a.b a.c a.c.d)
           ) == {:error, "Operation content is missing required keys: a.c.d"}
  end
end
