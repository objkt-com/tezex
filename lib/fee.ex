defmodule Tezex.Fee do
  alias Tezex.ForgeOperation

  @default_transaction_gas_limit 3_040
  @default_transaction_storage_limit 257
  @minimal_fees 100
  @minimal_mutez_per_byte 1
  @minimal_nanotez_per_gas_unit 100
  @reserve 10

  @hard_gas_limit_per_operation 1_040_000
  @hard_storage_limit_per_operation 60_000
  @default_gas_reserve 100

  # size of serialized branch and signature + safe reserve
  @extra_size 32 + 64
  # a tz4 (BLS) signature is 96 bytes, not 64
  @bls_extra_size 32 + 96
  # fee, gas_limit and storage_limit values (+3 bytes)
  @limits_extra_size 3 * 3

  def hard_gas_limit_per_operation, do: @hard_gas_limit_per_operation
  def hard_storage_limit_per_operation, do: @hard_storage_limit_per_operation
  def extra_size, do: @extra_size
  def default_gas_reserve, do: @default_gas_reserve

  @doc """
  Size of the serialized branch and signature of an operation signed by `source`.
  """
  @spec extra_size(String.t() | nil) :: pos_integer()
  def extra_size("tz4" <> _), do: @bls_extra_size
  def extra_size(_source), do: @extra_size

  @spec calculate_fee(map(), pos_integer(),
          extra_size: pos_integer(),
          minimal_nanotez_per_gas_unit: pos_integer()
        ) :: {:ok, pos_integer()} | {:error, ForgeOperation.error_reason()}
  def calculate_fee(content, consumed_gas, opts \\ []) do
    extra_size = Keyword.get(opts, :extra_size, extra_size(content["source"]))

    minimal_nanotez_per_gas_unit =
      Keyword.get(opts, :minimal_nanotez_per_gas_unit, @minimal_nanotez_per_gas_unit)

    case ForgeOperation.operation(content) do
      {:ok, forged_content} ->
        size = byte_size(forged_content) + extra_size

        fee =
          @minimal_fees + @minimal_mutez_per_byte * size +
            div(minimal_nanotez_per_gas_unit * consumed_gas, 1000)

        fees = fee + @reserve
        {:ok, fees}

      err ->
        err
    end
  end

  @doc """
  Fee for a content before simulation, with its gas limit standing in for the consumed gas.
  """
  @spec default_fee(map(), pos_integer()) ::
          {:ok, pos_integer()} | {:error, ForgeOperation.error_reason()}
  def default_fee(content, gas_limit) do
    calculate_fee(content, gas_limit,
      extra_size: extra_size(content["source"]) + @limits_extra_size
    )
  end

  def default_gas_limit(content) do
    case content["kind"] do
      "reveal" ->
        case content["source"] do
          "tz1" <> _ -> 176
          "tz2" <> _ -> 162
          "tz3" <> _ -> 1101
          "tz4" <> _ -> 1681
          source -> raise "Unknown default gas limit for reveal on `#{source}`"
        end

      "delegation" ->
        1000

      kind
      when kind in ~w(origination register_global_constant transfer_ticket smart_rollup_add_messages smart_rollup_execute_outbox_message) ->
        @hard_gas_limit_per_operation

      "transaction" ->
        if originated_account?(content["destination"]) do
          @hard_gas_limit_per_operation
        else
          @default_transaction_gas_limit
        end
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
        if originated_account?(content["destination"]) do
          @hard_storage_limit_per_operation
        else
          @default_transaction_storage_limit
        end

      kind
      when kind in ~w(register_global_constant transfer_ticket smart_rollup_add_messages smart_rollup_execute_outbox_message) ->
        @hard_storage_limit_per_operation
    end
  end

  defp originated_account?("KT1" <> _), do: true
  defp originated_account?(_), do: false
end
