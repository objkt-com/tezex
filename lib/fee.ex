defmodule Tezex.Fee do
  alias Tezex.ForgeOperation

  @default_transaction_gas_limit 1451
  @default_transaction_storage_limit 257
  @hard_gas_limit_per_operation 1_040_000
  @hard_storage_limit_per_operation 60000
  @minimal_fees 100
  @minimal_mutez_per_byte 1
  @minimal_nanotez_per_gas_unit 100
  @reserve 10

  # size of serialized branch and signature + safe reserve
  @extra_size 32 + 64

  def extra_size, do: @extra_size

  @default_gas_reserve 100

  def default_gas_reserve, do: @default_gas_reserve

  @spec calculate_fee(map(), pos_integer(),
          extra_size: pos_integer(),
          minimal_nanotez_per_gas_unit: pos_integer()
        ) :: pos_integer()
  def calculate_fee(content, consumed_gas, opts \\ []) do
    extra_size = Keyword.get(opts, :extra_size, @extra_size)

    minimal_nanotez_per_gas_unit =
      Keyword.get(opts, :minimal_nanotez_per_gas_unit, @minimal_nanotez_per_gas_unit)

    size = byte_size(ForgeOperation.operation(content)) + extra_size

    fee =
      @minimal_fees + @minimal_mutez_per_byte * size +
        div(minimal_nanotez_per_gas_unit * consumed_gas, 1000)

    fee + @reserve
  end

  # Voir pour utiliser hard_gas_limit_per_content aussi ?
  def default_gas_limit(content) do
    case content["kind"] do
      "reveal" ->
        case content["source"] do
          "tz1" <> _ -> 176
          "tz2" <> _ -> 162
          "tz3" <> _ -> 1101
          "tz4" <> _ -> 1681
        end

      "delegation" ->
        1000

      kind
      when kind in ~w(origination register_global_constant transfer_ticket smart_rollup_add_messages smart_rollup_execute_outbox_message) ->
        @hard_gas_limit_per_operation

      "transaction" ->
        if String.starts_with?(content["destination"], "KT"),
          do: @hard_gas_limit_per_operation,
          else: @default_transaction_gas_limit
    end
  end

  def default_storage_limit(content) do
    case content["kind"] do
      "reveal" ->
        0

      "delegation" ->
        0

      "origination" ->
        @hard_storage_limit_per_operation

      "transaction" ->
        if String.starts_with?(content["destination"], "KT"),
          do: @hard_storage_limit_per_operation,
          else: @default_transaction_storage_limit

      kind
      when kind in ~w(register_global_constant transfer_ticket smart_rollup_add_messages smart_rollup_execute_outbox_message) ->
        @hard_storage_limit_per_operation
    end
  end
end
