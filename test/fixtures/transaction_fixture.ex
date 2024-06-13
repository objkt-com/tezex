defmodule Tezex.TransactionFixture do
  def transfer(destination) do
    %{
      "amount" => "100",
      "destination" => destination,
      "kind" => "transaction"
    }
  end

  def offer(offer_address) do
    [
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
                                  "string" => offer_address
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
  end
end
