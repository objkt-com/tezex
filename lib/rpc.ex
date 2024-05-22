defmodule Tezex.Rpc do
  alias Tezex.Crypto
  alias Tezex.ForgeOperation
  alias Tezex.Rpc
  alias Tezex.Fee

  @type t() :: %__MODULE__{
          endpoint: binary(),
          chain_id: binary(),
          headers: Finch.Request.headers(),
          opts: Finch.request_opts()
        }

  defstruct [:endpoint, chain_id: "main", headers: [], opts: []]

  def prepare_operation(contents, wallet_address, counter, branch) do
    contents =
      contents
      |> Enum.with_index(counter)
      |> Enum.map(fn {content, counter} ->
        Map.merge(content, %{
          "counter" => Integer.to_string(counter),
          "source" => wallet_address,
          "gas_limit" => Integer.to_string(Fee.default_gas_limit(content)),
          "storage_limit" => Integer.to_string(Fee.default_storage_limit(content)),
          "fee" => "0"
        })
      end)

    %{
      "branch" => branch,
      "contents" => contents
    }
  end

  def fill_operation_fee(operation, operation_result, opts \\ []) do
    storage_limit = Keyword.get(opts, :storage_limit)

    applied? =
      Enum.all?(operation_result, &(&1["metadata"]["operation_result"]["status"] == "applied"))

    unless applied? do
      raise inspect(Enum.map(operation_result, & &1["metadata"]["operation_result"]["errors"]))
    end

    number_contents = length(operation_result)

    contents =
      Enum.map(operation_result, fn content ->
        if validation_passes(content["kind"]) == 3 do
          consumed_milligas =
            case content["metadata"]["operation_result"]["consumed_milligas"] do
              nil -> 0
              v -> String.to_integer(v)
            end

          gas_limit_new = ceil(consumed_milligas / 1000)

          gas_limit_new =
            if content["kind"] in ~w(origination transaction) do
              gas_limit_new + Fee.default_gas_reserve()
            else
              gas_limit_new
            end

          storage_limit_new =
            if is_nil(storage_limit) do
              paid_storage_size_diff =
                case content["metadata"]["operation_result"]["paid_storage_size_diff"] do
                  nil -> 0
                  v -> String.to_integer(v)
                end

              burned =
                case content["metadata"]["operation_result"]["allocated_destination_contract"] ||
                       content["metadata"]["operation_result"]["originated_contracts"] do
                  nil -> 0
                  _ -> 257
                end

              paid_storage_size_diff + burned
            else
              div(storage_limit, number_contents)
            end

          content = Map.drop(content, ~w(metadata))

          extra_size = 1 + div(Fee.extra_size(), number_contents)
          fee = Fee.calculate_fee(content, gas_limit_new, extra_size: extra_size)

          %{
            content
            | "gas_limit" => Integer.to_string(gas_limit_new),
              "storage_limit" => Integer.to_string(storage_limit_new),
              "fee" => Integer.to_string(fee)
          }
        else
          content
        end
      end)

    %{operation | "contents" => contents}
  end

  def send_operation(%Rpc{} = rpc, contents, wallet_address, encoded_private_key, opts \\ []) do
    offset = Keyword.get(opts, :offset, 0)

    {:ok, block_head} = get_block_at_offset(rpc, offset)

    branch = binary_part(block_head["hash"], 0, 51)
    protocol = block_head["protocol"]

    counter = get_next_counter_for_account(rpc, wallet_address)
    operation = prepare_operation(contents, wallet_address, counter, branch)

    {:ok, [%{"contents" => operation_result}]} =
      preapply_operation(rpc, operation, encoded_private_key, protocol)

    operation = fill_operation_fee(operation, operation_result, opts)

    payload = injection_payload(operation, encoded_private_key)

    inject_operation(rpc, payload)
  end

  def injection_payload(operation, encoded_private_key) do
    forged_operation = ForgeOperation.operation_group(operation)

    signature = Crypto.sign_operation(encoded_private_key, forged_operation)

    payload_signature =
      signature
      |> Crypto.decode_signature!()
      |> Base.encode16(case: :lower)

    forged_operation <> payload_signature
  end

  # NOTE: Explanation: https://pytezos.baking-bad.org/tutorials/02.html#operation-group
  defp validation_passes(kind) do
    case kind do
      "failing_noop" -> -1
      "endorsement" -> 0
      "endorsement_with_slot" -> 0
      "proposals" -> 1
      "ballot" -> 1
      "seed_nonce_revelation" -> 2
      "double_endorsement_evidence" -> 2
      "double_baking_evidence" -> 2
      "activate_account" -> 2
      "reveal" -> 3
      "transaction" -> 3
      "origination" -> 3
      "delegation" -> 3
      "register_global_constant" -> 3
      "transfer_ticket" -> 3
      "smart_rollup_add_messages" -> 3
      "smart_rollup_execute_outbox_message" -> 3
    end
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

  @doc """
  Simulate the application of the operations with the context of the given block and return the result of each operation application.
  """
  def preapply_operation(%Rpc{} = rpc, operation, encoded_private_key, protocol) do
    forged_operation = ForgeOperation.operation_group(operation)

    signature = Crypto.sign_operation(encoded_private_key, forged_operation)

    payload = [Map.merge(operation, %{"signature" => signature, "protocol" => protocol})]

    post(rpc, "/blocks/head/helpers/preapply/operations", payload)
  end

  def inject_operation(%Rpc{} = rpc, payload) do
    post(rpc, "/injection/operation", payload)
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

    url =
      if String.starts_with?(path, "/blocks") do
        URI.append_path(url, "/chains/#{rpc.chain_id}")
      else
        URI.append_query(url, URI.encode_query(%{"chain" => rpc.chain_id}))
      end

    url =
      url
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
