defmodule Tezex.Transaction do
  alias Tezex.Transaction

  @type t() :: %__MODULE__{
          source: binary() | nil,
          destination: binary(),
          fee: pos_integer() | nil,
          counter: integer() | nil,
          gas_limit: pos_integer() | nil,
          amount: pos_integer() | nil,
          destination: binary(),
          storage_limit: pos_integer() | nil,
          parameters: map() | nil
        }

  defstruct [
    :kind,
    :destination,
    :source,
    fee: 0,
    counter: 0,
    gas_limit: 0,
    amount: 0,
    storage_limit: 0,
    parameters: nil
  ]

  defimpl Jason.Encoder do
    def encode(%Transaction{parameters: nil} = transaction, opts) do
      transaction
      |> Map.from_struct()
      |> Map.drop([:parameters])
      |> encode(opts)
    end

    def encode(%Transaction{} = transaction, opts) do
      transaction
      |> Map.from_struct()
      |> encode(opts)
    end

    def encode(value, opts) do
      value
      |> Map.update!(:fee, &to_string/1)
      |> Map.update!(:gas_limit, &to_string/1)
      |> Map.update!(:amount, &to_string/1)
      |> Map.update!(:storage_limit, &to_string/1)
      |> Map.update!(:counter, &to_string/1)
      |> Jason.Encode.map(opts)
    end
  end
end
