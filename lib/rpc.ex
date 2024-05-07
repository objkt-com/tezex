defmodule Tezex.Rpc do
  alias Tezex.Crypto
  alias Tezex.ForgeOperation
  alias Tezex.Rpc

  @type t() :: %__MODULE__{
          endpoint: binary(),
          chain_id: binary(),
          headers: Finch.Request.headers(),
          opts: Finch.request_opts()
        }

  defstruct [:endpoint, chain_id: "main", headers: [], opts: []]

  # Various constants for the Tezos platforms. Fees are expressed in µtz unless otherwise noted, storage unit is bytes.
  # @operation_group_watermark <<3>>

  # @default_simple_transaction_fee 1420
  # @default_transaction_storage_limit 496
  # @default_transaction_gas_limit 10600

  # @default_delegation_fee 1258
  # @default_delegation_storage_limit 0
  # @default_delegation_gas_limit 1100

  # @default_key_reveal_fee 1270
  # @default_key_reveal_storage_limit 0
  # @default_key_reveal_gas_limit 1100

  # @p005_manager_contract_withdrawal_gas_limit 26283
  # @p005_manager_contract_deposit_gas_limit 15285
  # @p005_manager_contract_withdrawal_storage_limit 496

  # @p001_storage_rate 1_000_000 / 1000
  # @p007_storage_rate 250_000 / 1000
  # @storage_rate @p007_storage_rate

  # @base_operation_fee 100

  # @p009_block_gas_cap 10_400_000
  # @p010_block_gas_cap 5_200_000
  # @p016_block_gas_cap 2_600_000
  # @p007_operation_gas_cap 1_040_000
  # @operation_gas_cap @p007_operation_gas_cap
  # @block_gas_cap @p016_block_gas_cap

  # @p010_operation_storage_cap 60_000
  # @p011_operation_storage_cap 32_768
  # @operation_storage_cap @p011_operation_storage_cap

  # @empty_account_storage_burn 257

  # @default_baker_vig 200

  # @gas_limit_padding 1000
  # @storage_limit_padding 25

  # @head_branch_offset 54
  # @max_branch_offset 64

  # Outbound operation queue timeout in seconds. After this period, TezosOperationQueue will attempt to submit the transactions currently in queue.
  # @default_batch_delay 25

  # @p009_block_time 60
  # @p010_block_time 30
  # @default_block_time @p010_block_time

  # @genesis_block_time ~U[2018-06-30 10:07:32.000Z]

  def send_operation(%Rpc{} = rpc, contents, wallet_address, encoded_private_key, offset \\ 0) do
    {:ok, block_head} = get_block_at_offset(rpc, offset)
    branch = binary_part(block_head["hash"], 0, 51)

    counter = get_next_counter_for_account(rpc, wallet_address)

    contents =
      contents
      |> Enum.with_index()
      |> Enum.map(fn {c, i} ->
        Map.merge(c, %{"counter" => Integer.to_string(counter + i), "source" => wallet_address})
      end)

    operation = %{
      "branch" => branch,
      "contents" => contents
    }

    forged_operation = ForgeOperation.operation_group(operation)

    signature = Crypto.sign_operation(encoded_private_key, forged_operation)
    {:ok, decoded_signature} = Crypto.decode_signature(signature)

    decoded_signature = Base.encode16(decoded_signature, case: :lower)

    inject_operation(rpc, forged_operation, decoded_signature)
  end

  def get_counter_for_account(%Rpc{} = rpc, address) do
    with {:ok, n} <- get(rpc, "/blocks/head/context/contracts/#{address}/counter"),
         {n, ""} <- Integer.parse(n) do
      n
    end
  end

  def get_next_counter_for_account(%Rpc{} = rpc, address) do
    get_counter_for_account(rpc, address) + 1
  end

  def get_block(%Rpc{} = rpc, hash \\ "head") do
    get(rpc, "/blocks/#{hash}")
  end

  def get_block_at_offset(%Rpc{} = rpc, offset) do
    if offset <= 0 do
      get_block(rpc)
    end

    {:ok, head} = get_block(rpc)
    get(rpc, "/blocks/#{head["header"]["level"] - offset}")
  end

  def inject_operation(%Rpc{} = rpc, forged_operation, signature) do
    post(rpc, "/injection/operation", forged_operation <> signature)
  end

  defp get(%Rpc{} = rpc, path) do
    url =
      URI.parse(rpc.endpoint)
      |> URI.append_path("/chains/#{rpc.chain_id}")
      |> URI.append_path(path)
      |> URI.to_string()

    Finch.build(:get, url, rpc.headers)
    |> Finch.request(Tezex.Finch, rpc.opts)
    |> case do
      {:ok, %Finch.Response{status: 200, body: body}} -> Jason.decode(body)
      {:error, _} = err -> err
    end
  end

  defp post(%Rpc{} = rpc, path, body) do
    url =
      URI.parse(rpc.endpoint)
      |> URI.append_query(URI.encode_query(%{"chain" => rpc.chain_id}))
      |> URI.append_path(path)
      |> URI.to_string()

    body = Jason.encode!(body)

    Finch.build(:post, url, rpc.headers, body)
    |> Finch.request(Tezex.Finch, rpc.opts)
    |> case do
      {:ok, %Finch.Response{status: 200, body: body}} -> Jason.decode(body)
      {:error, _} = err -> err
    end
  end
end
