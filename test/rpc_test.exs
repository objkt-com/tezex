defmodule Tezex.RpcTest do
  use ExUnit.Case, async: true

  alias Tezex.Rpc
  doctest Tezex.Rpc, import: true

  @endpoint "https://ghostnet.tezos.marigold.dev/"
  @ghostnet_1_address "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew"
  @ghostnet_1_pkey "edsk33h91RysSBUiYyEWbeRwo41YeZrtMPTNsuZ9nzsYWwiV8CFyKi"
  @ghostnet_2_address "tz1cMcDFLgFe2picQbo4DY1i6mZJiVhPCu5B"

  @tag :tezos
  test "get_counter_for_account" do
    counter =
      Rpc.get_counter_for_account(
        %Rpc{endpoint: @endpoint},
        "tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z"
      )

    assert is_integer(counter)
  end

  test "prepare_operation/4" do
    contents = [
      %{
        "amount" => "100",
        "destination" => @ghostnet_2_address,
        "kind" => "transaction"
      }
    ]

    counter = 1123
    branch = "BLWdshvgEYbtUaABnmqkMuyMezpfsu36DEJPDJN63CW3TFuk7bP"

    assert %{
             "branch" => "BLWdshvgEYbtUaABnmqkMuyMezpfsu36DEJPDJN63CW3TFuk7bP",
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
           } ==
             Rpc.prepare_operation(
               contents,
               @ghostnet_1_address,
               counter,
               branch
             )
  end

  test "forge_and_sign_operation/2" do
    operation = %{
      "branch" => "BLWdshvgEYbtUaABnmqkMuyMezpfsu36DEJPDJN63CW3TFuk7bP",
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

    assert result == Rpc.forge_and_sign_operation(operation, @ghostnet_1_pkey)
  end

  describe "fill_operation_fee/3" do
    test "a contract operation" do
      operation = %{
        "contents" => [
          %{
            "kind" => "transaction",
            "amount" => "1000000",
            "destination" => "KT1MFWsAXGUZ4gFkQnjByWjrrVtuQi4Tya8G",
            "parameters" => %{
              "entrypoint" => "offer",
              "value" => %{
                "prim" => "Pair",
                "args" => [
                  %{
                    "prim" => "Pair",
                    "args" => [
                      %{
                        "string" => "KT1L9L24QjU4qHmej6j1G5DTqhZanPxHH5ie"
                      },
                      %{
                        "prim" => "Some",
                        "args" => [
                          %{
                            "int" => "0"
                          }
                        ]
                      }
                    ]
                  },
                  %{
                    "prim" => "Pair",
                    "args" => [
                      %{
                        "prim" => "Right",
                        "args" => [
                          %{
                            "prim" => "Right",
                            "args" => [
                              %{
                                "prim" => "Unit"
                              }
                            ]
                          }
                        ]
                      },
                      %{
                        "prim" => "Pair",
                        "args" => [
                          %{
                            "int" => "1000000"
                          },
                          %{
                            "prim" => "Pair",
                            "args" => [
                              [
                                %{
                                  "prim" => "Elt",
                                  "args" => [
                                    %{
                                      "string" => @ghostnet_1_address
                                    },
                                    %{
                                      "int" => "1000"
                                    }
                                  ]
                                }
                              ],
                              %{
                                "prim" => "Pair",
                                "args" => [
                                  %{
                                    "prim" => "None"
                                  },
                                  %{
                                    "prim" => "Pair",
                                    "args" => [
                                      [],
                                      %{
                                        "prim" => "Pair",
                                        "args" => [
                                          %{
                                            "prim" => "None"
                                          },
                                          %{
                                            "prim" => "None"
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
                    ]
                  }
                ]
              }
            }
          }
        ]
      }

      operation_result = [
        %{
          "amount" => "1000000",
          "counter" => "26949360",
          "destination" => "KT1MFWsAXGUZ4gFkQnjByWjrrVtuQi4Tya8G",
          "fee" => "0",
          "gas_limit" => "1040000",
          "kind" => "transaction",
          "metadata" => %{
            "operation_result" => %{
              "consumed_milligas" => "2318760",
              "paid_storage_size_diff" => "189",
              "status" => "applied",
              "storage_size" => "110701"
            }
          },
          "parameters" => %{
            "entrypoint" => "offer",
            "value" => %{
              "args" => [
                %{
                  "args" => [
                    %{"string" => "KT1L9L24QjU4qHmej6j1G5DTqhZanPxHH5ie"},
                    %{"args" => [%{"int" => "0"}], "prim" => "Some"}
                  ],
                  "prim" => "Pair"
                },
                %{
                  "args" => [
                    %{
                      "args" => [
                        %{"args" => [%{"prim" => "Unit"}], "prim" => "Right"}
                      ],
                      "prim" => "Right"
                    },
                    %{
                      "args" => [
                        %{"int" => "1000000"},
                        %{
                          "args" => [
                            [
                              %{
                                "args" => [
                                  %{
                                    "string" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew"
                                  },
                                  %{"int" => "1000"}
                                ],
                                "prim" => "Elt"
                              }
                            ],
                            %{
                              "args" => [
                                %{"prim" => "None"},
                                %{
                                  "args" => [
                                    [],
                                    %{
                                      "args" => [
                                        %{"prim" => "None"},
                                        %{"prim" => "None"}
                                      ],
                                      "prim" => "Pair"
                                    }
                                  ],
                                  "prim" => "Pair"
                                }
                              ],
                              "prim" => "Pair"
                            }
                          ],
                          "prim" => "Pair"
                        }
                      ],
                      "prim" => "Pair"
                    }
                  ],
                  "prim" => "Pair"
                }
              ],
              "prim" => "Pair"
            }
          },
          "source" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
          "storage_limit" => "60000"
        }
      ]

      assert %{
               "contents" => [
                 %{
                   "amount" => "1000000",
                   "counter" => "26949360",
                   "destination" => "KT1MFWsAXGUZ4gFkQnjByWjrrVtuQi4Tya8G",
                   "fee" => "651",
                   "gas_limit" => "2419",
                   "kind" => "transaction",
                   "source" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
                   "storage_limit" => "189"
                 }
               ]
             } =
               Rpc.fill_operation_fee(operation, operation_result)
    end

    test "a transfer" do
      operation = %{
        "contents" => [
          %{
            "amount" => "100",
            "counter" => "1",
            "destination" => "tz1cMcDFLgFe2picQbo4DY1i6mZJiVhPCu5B",
            "fee" => "0",
            "gas_limit" => "0",
            "kind" => "transaction",
            "source" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
            "storage_limit" => "0"
          }
        ]
      }

      operation_result = [
        %{
          "amount" => "100",
          "counter" => "1",
          "destination" => "tz1cMcDFLgFe2picQbo4DY1i6mZJiVhPCu5B",
          "fee" => "0",
          "gas_limit" => "1451",
          "kind" => "transaction",
          "metadata" => %{
            "operation_result" => %{
              "consumed_milligas" => "168721",
              "status" => "applied"
            }
          },
          "source" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew",
          "storage_limit" => "257"
        }
      ]

      assert %{
               "contents" => [
                 %{
                   "amount" => "100",
                   "fee" => "285",
                   "gas_limit" => "269",
                   "storage_limit" => "0"
                 }
               ]
             } =
               Rpc.fill_operation_fee(operation, operation_result)
    end
  end

  describe "send_operation/4" do
    @describetag :tezos

    test "a contract operation" do
      rpc = %Rpc{endpoint: @endpoint}

      contents = [
        %{
          "kind" => "transaction",
          "amount" => "1000000",
          "destination" => "KT1MFWsAXGUZ4gFkQnjByWjrrVtuQi4Tya8G",
          "parameters" => %{
            "entrypoint" => "offer",
            "value" => %{
              "prim" => "Pair",
              "args" => [
                %{
                  "prim" => "Pair",
                  "args" => [
                    %{
                      "string" => "KT1L9L24QjU4qHmej6j1G5DTqhZanPxHH5ie"
                    },
                    %{
                      "prim" => "Some",
                      "args" => [
                        %{
                          "int" => "0"
                        }
                      ]
                    }
                  ]
                },
                %{
                  "prim" => "Pair",
                  "args" => [
                    %{
                      "prim" => "Right",
                      "args" => [
                        %{
                          "prim" => "Right",
                          "args" => [
                            %{
                              "prim" => "Unit"
                            }
                          ]
                        }
                      ]
                    },
                    %{
                      "prim" => "Pair",
                      "args" => [
                        %{
                          "int" => "1000000"
                        },
                        %{
                          "prim" => "Pair",
                          "args" => [
                            [
                              %{
                                "prim" => "Elt",
                                "args" => [
                                  %{
                                    "string" => @ghostnet_1_address
                                  },
                                  %{
                                    "int" => "1000"
                                  }
                                ]
                              }
                            ],
                            %{
                              "prim" => "Pair",
                              "args" => [
                                %{
                                  "prim" => "None"
                                },
                                %{
                                  "prim" => "Pair",
                                  "args" => [
                                    [],
                                    %{
                                      "prim" => "Pair",
                                      "args" => [
                                        %{
                                          "prim" => "None"
                                        },
                                        %{
                                          "prim" => "None"
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
                  ]
                }
              ]
            }
          }
        }
      ]

      assert {:ok, operation_id} =
               Rpc.send_operation(rpc, contents, @ghostnet_1_address, @ghostnet_1_pkey)

      assert is_binary(operation_id)
    end

    test "a transfer" do
      rpc = %Rpc{endpoint: @endpoint}

      contents = %{
        "amount" => "100",
        "destination" => @ghostnet_2_address,
        "kind" => "transaction"
      }

      assert {:ok, operation_id} =
               Rpc.send_operation(rpc, contents, @ghostnet_1_address, @ghostnet_1_pkey)

      assert is_binary(operation_id)
    end
  end

  @tag :tezos
  test "raise" do
    rpc = %Rpc{endpoint: @endpoint}

    contents = [
      %{
        "amount" => "1000000000",
        "destination" => @ghostnet_2_address,
        "kind" => "transaction"
      }
    ]

    assert_raise RuntimeError, fn ->
      Rpc.send_operation(rpc, contents, @ghostnet_1_address, @ghostnet_1_pkey)
    end
  end
end
