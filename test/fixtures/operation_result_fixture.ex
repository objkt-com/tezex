defmodule Tezex.OperationResultFixture do
  def transfer do
    [
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
  end

  def settle_auction do
    [
      %{
        "amount" => "0",
        "counter" => "27648099",
        "destination" => "KT1Mn95duVDaYjQnwcWNgE4d21TwJVMobXw1",
        "fee" => "0",
        "gas_limit" => "1040000",
        "kind" => "transaction",
        "metadata" => %{
          "internal_operation_results" => [
            %{
              "amount" => "0",
              "destination" => "KT1MzhWSxXQv7hwK2fWgW8SpeLZ1c6vXYHQb",
              "kind" => "transaction",
              "nonce" => 0,
              "parameters" => %{},
              "result" => %{
                "consumed_milligas" => "6323955",
                "lazy_storage_diff" => [],
                "status" => "applied",
                "storage" => [
                  [
                    %{
                      "args" => [
                        %{"bytes" => "000032b7ad03806fc1ec76863deba77145ed46c98807"},
                        %{"int" => "340364"}
                      ],
                      "prim" => "Pair"
                    },
                    %{"int" => "340365"},
                    %{"int" => "12"},
                    %{"int" => "340366"}
                  ],
                  %{
                    "args" => [
                      %{"int" => "340367"},
                      %{
                        "args" => [%{"int" => "340368"}, %{"int" => "340369"}],
                        "prim" => "Pair"
                      }
                    ],
                    "prim" => "Pair"
                  },
                  %{"int" => "340370"},
                  %{"int" => "340371"},
                  %{"int" => "340372"}
                ],
                "storage_size" => "14526"
              },
              "source" => "KT1Mn95duVDaYjQnwcWNgE4d21TwJVMobXw1"
            },
            %{
              "amount" => "0",
              "destination" => "KT1RBL4nu4t7LSfCDxmWyV8GwSn9so1jbozD",
              "kind" => "transaction",
              "nonce" => 1,
              "parameters" => %{
                "entrypoint" => "transfer",
                "value" => %{
                  "args" => [
                    %{"bytes" => "0190c02bad2719cd206f4d71399fd565b37b376a5300"},
                    %{
                      "args" => [
                        %{"bytes" => "000032b7ad03806fc1ec76863deba77145ed46c98807"},
                        %{"int" => "1200000"}
                      ],
                      "prim" => "Pair"
                    }
                  ],
                  "prim" => "Pair"
                }
              },
              "result" => %{
                "consumed_milligas" => "3114497",
                "lazy_storage_diff" => [
                  %{
                    "diff" => %{"action" => "update", "updates" => []},
                    "id" => "327612",
                    "kind" => "big_map"
                  },
                  %{
                    "diff" => %{"action" => "update", "updates" => []},
                    "id" => "327611",
                    "kind" => "big_map"
                  },
                  %{
                    "diff" => %{
                      "action" => "update",
                      "updates" => [
                        %{
                          "key" => %{
                            "bytes" => "000032b7ad03806fc1ec76863deba77145ed46c98807"
                          },
                          "key_hash" => "exprvLsQmTghpXiMr1KnMj3qCniAJX3BNqbnU9qYpN6QdM7T2uyPF1",
                          "value" => %{
                            "args" => [
                              [
                                %{
                                  "args" => [
                                    %{
                                      "bytes" => "0190c02bad2719cd206f4d71399fd565b37b376a5300"
                                    },
                                    %{"int" => "0"}
                                  ],
                                  "prim" => "Elt"
                                },
                                %{
                                  "args" => [
                                    %{
                                      "bytes" => "01e6cbe60a4be4b77bb156ad44135a6b58cc79a8c300"
                                    },
                                    %{"int" => "1000000000000000000000000000000"}
                                  ],
                                  "prim" => "Elt"
                                }
                              ],
                              %{"int" => "102200000"}
                            ],
                            "prim" => "Pair"
                          }
                        },
                        %{
                          "key" => %{
                            "bytes" => "0190c02bad2719cd206f4d71399fd565b37b376a5300"
                          },
                          "key_hash" => "expru3Rsy9seEKZ7PSP3SAJLPWMHCDWgi1ywWY4rJW8ewE7Q8txWm7",
                          "value" => %{
                            "args" => [[], %{"int" => "11800000"}],
                            "prim" => "Pair"
                          }
                        }
                      ]
                    },
                    "id" => "327610",
                    "kind" => "big_map"
                  }
                ],
                "status" => "applied",
                "storage" => [
                  %{
                    "args" => [%{"int" => "327610"}, %{"int" => "327611"}],
                    "prim" => "Pair"
                  },
                  %{"bytes" => "01a39b37004846441749651bad821d1589fc4e24b300"},
                  %{"int" => "327612"},
                  %{"int" => "8711000000"}
                ],
                "storage_size" => "4450"
              },
              "source" => "KT1Mn95duVDaYjQnwcWNgE4d21TwJVMobXw1"
            },
            %{
              "amount" => "0",
              "destination" => "KT1RBL4nu4t7LSfCDxmWyV8GwSn9so1jbozD",
              "kind" => "transaction",
              "nonce" => 2,
              "parameters" => %{
                "entrypoint" => "transfer",
                "value" => %{
                  "args" => [
                    %{"bytes" => "0190c02bad2719cd206f4d71399fd565b37b376a5300"},
                    %{
                      "args" => [
                        %{"bytes" => "00008b86921a84c9df3460153cf674145dccce1da4fd"},
                        %{"int" => "600000"}
                      ],
                      "prim" => "Pair"
                    }
                  ],
                  "prim" => "Pair"
                }
              },
              "result" => %{
                "balance_updates" => [
                  %{
                    "change" => "-250",
                    "contract" => "tz1gVpau5T9ZtCtLBnRCyNVm5HUTQK9LupUU",
                    "kind" => "contract",
                    "origin" => "block"
                  },
                  %{
                    "category" => "storage fees",
                    "change" => "250",
                    "kind" => "burned",
                    "origin" => "block"
                  }
                ],
                "consumed_milligas" => "3092284",
                "lazy_storage_diff" => [
                  %{
                    "diff" => %{"action" => "update", "updates" => []},
                    "id" => "327612",
                    "kind" => "big_map"
                  },
                  %{
                    "diff" => %{"action" => "update", "updates" => []},
                    "id" => "327611",
                    "kind" => "big_map"
                  },
                  %{
                    "diff" => %{
                      "action" => "update",
                      "updates" => [
                        %{
                          "key" => %{
                            "bytes" => "00008b86921a84c9df3460153cf674145dccce1da4fd"
                          },
                          "key_hash" => "exprv4qEXKFAxZR6JVdP8Zv1kp8N9GSKXt8yyw4eKFqCQZzVCwuPfH",
                          "value" => %{
                            "args" => [[], %{"int" => "1625000"}],
                            "prim" => "Pair"
                          }
                        },
                        %{
                          "key" => %{
                            "bytes" => "0190c02bad2719cd206f4d71399fd565b37b376a5300"
                          },
                          "key_hash" => "expru3Rsy9seEKZ7PSP3SAJLPWMHCDWgi1ywWY4rJW8ewE7Q8txWm7",
                          "value" => %{
                            "args" => [[], %{"int" => "11200000"}],
                            "prim" => "Pair"
                          }
                        }
                      ]
                    },
                    "id" => "327610",
                    "kind" => "big_map"
                  }
                ],
                "paid_storage_size_diff" => "1",
                "status" => "applied",
                "storage" => [
                  %{
                    "args" => [%{"int" => "327610"}, %{"int" => "327611"}],
                    "prim" => "Pair"
                  },
                  %{"bytes" => "01a39b37004846441749651bad821d1589fc4e24b300"},
                  %{"int" => "327612"},
                  %{"int" => "8711000000"}
                ],
                "storage_size" => "4451"
              },
              "source" => "KT1Mn95duVDaYjQnwcWNgE4d21TwJVMobXw1"
            },
            %{
              "amount" => "0",
              "destination" => "KT1RBL4nu4t7LSfCDxmWyV8GwSn9so1jbozD",
              "kind" => "transaction",
              "nonce" => 3,
              "parameters" => %{
                "entrypoint" => "transfer",
                "value" => %{
                  "args" => [
                    %{"bytes" => "0190c02bad2719cd206f4d71399fd565b37b376a5300"},
                    %{
                      "args" => [
                        %{"bytes" => "00007fc95c97fd368cd9055610ee79e64ff9e0b5285c"},
                        %{"int" => "10200000"}
                      ],
                      "prim" => "Pair"
                    }
                  ],
                  "prim" => "Pair"
                }
              },
              "result" => %{
                "balance_updates" => [
                  %{
                    "change" => "-500",
                    "contract" => "tz1gVpau5T9ZtCtLBnRCyNVm5HUTQK9LupUU",
                    "kind" => "contract",
                    "origin" => "block"
                  },
                  %{
                    "category" => "storage fees",
                    "change" => "500",
                    "kind" => "burned",
                    "origin" => "block"
                  }
                ],
                "consumed_milligas" => "3102043",
                "lazy_storage_diff" => [
                  %{
                    "diff" => %{"action" => "update", "updates" => []},
                    "id" => "327612",
                    "kind" => "big_map"
                  },
                  %{
                    "diff" => %{"action" => "update", "updates" => []},
                    "id" => "327611",
                    "kind" => "big_map"
                  },
                  %{
                    "diff" => %{
                      "action" => "update",
                      "updates" => [
                        %{
                          "key" => %{
                            "bytes" => "0190c02bad2719cd206f4d71399fd565b37b376a5300"
                          },
                          "key_hash" => "expru3Rsy9seEKZ7PSP3SAJLPWMHCDWgi1ywWY4rJW8ewE7Q8txWm7",
                          "value" => %{
                            "args" => [[], %{"int" => "1000000"}],
                            "prim" => "Pair"
                          }
                        },
                        %{
                          "key" => %{
                            "bytes" => "00007fc95c97fd368cd9055610ee79e64ff9e0b5285c"
                          },
                          "key_hash" => "exprtdjJ5Usa5uaeZ5qnk9LWSzCEMG7Usf8kbtCW95N8JorJbpmB4G",
                          "value" => %{
                            "args" => [
                              [
                                %{
                                  "args" => [
                                    %{
                                      "bytes" => "0190c02bad2719cd206f4d71399fd565b37b376a5300"
                                    },
                                    %{"int" => "0"}
                                  ],
                                  "prim" => "Elt"
                                }
                              ],
                              %{"int" => "10200000"}
                            ],
                            "prim" => "Pair"
                          }
                        }
                      ]
                    },
                    "id" => "327610",
                    "kind" => "big_map"
                  }
                ],
                "paid_storage_size_diff" => "2",
                "status" => "applied",
                "storage" => [
                  %{
                    "args" => [%{"int" => "327610"}, %{"int" => "327611"}],
                    "prim" => "Pair"
                  },
                  %{"bytes" => "01a39b37004846441749651bad821d1589fc4e24b300"},
                  %{"int" => "327612"},
                  %{"int" => "8711000000"}
                ],
                "storage_size" => "4453"
              },
              "source" => "KT1Mn95duVDaYjQnwcWNgE4d21TwJVMobXw1"
            }
          ],
          "operation_result" => %{
            "consumed_milligas" => "5111003",
            "lazy_storage_diff" => [
              %{
                "diff" => %{"action" => "update", "updates" => []},
                "id" => "340239",
                "kind" => "big_map"
              },
              %{
                "diff" => %{
                  "action" => "update",
                  "updates" => [
                    %{
                      "key" => %{"int" => "1000007"},
                      "key_hash" => "exprv8URh8VAq2d6DxGSS1Jp7xeyfegWTLeeBNUKeZNVJUnAaBqGWf"
                    }
                  ]
                },
                "id" => "340238",
                "kind" => "big_map"
              }
            ],
            "status" => "applied",
            "storage" => [
              %{
                "args" => [
                  %{"int" => "340238"},
                  %{"bytes" => "01144361fae1d55b6ce1e1ce07b33a0415ea6e941100"}
                ],
                "prim" => "Pair"
              },
              %{"int" => "340239"},
              %{"int" => "1000050"},
              %{"bytes" => "0160cf50256d7599e2bfd12ac765c92e64207262ae00"}
            ],
            "storage_size" => "16415"
          }
        },
        "parameters" => %{
          "entrypoint" => "settle_auction",
          "value" => %{"int" => "1000007"}
        },
        "source" => "tz1gVpau5T9ZtCtLBnRCyNVm5HUTQK9LupUU",
        "storage_limit" => "60000"
      }
    ]
  end

  def offer() do
    [
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
  end
end
