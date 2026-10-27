defmodule Tezex.Rpc.EntrypointCache do
  @moduledoc """
  Cache for the results of `Tezex.Rpc.entrypoints/2` and `Tezex.Rpc.entrypoint/3`.

  The process only owns a named public ETS table. Callers read and write the
  table directly, so lookups never go through the process.

  Keys:

    * `{endpoint, chain_id, address}` for the entrypoint list of a contract
    * `{endpoint, chain_id, address, name}` for the type of one entrypoint

  The endpoint is part of the key so that two networks never share entries.
  A contract's code can't change once it is deployed, so entries never expire.
  Only `{:ok, _}` results are stored.
  """

  use GenServer

  @table __MODULE__

  @type key() ::
          {endpoint :: binary(), chain_id :: binary(), address :: binary()}
          | {endpoint :: binary(), chain_id :: binary(), address :: binary(), name :: binary()}

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  Return the cached value for `key` as `{:ok, value}`. On a miss, call `fun`,
  store its result if it is `{:ok, value}`, and return it.
  """
  @spec fetch(key(), (-> {:ok, value} | {:error, reason})) :: {:ok, value} | {:error, reason}
        when value: term(), reason: term()
  def fetch(key, fun) do
    case lookup(key) do
      {:ok, _} = hit -> hit
      :error -> fun.() |> store(key)
    end
  end

  @doc """
  Return `{:ok, value}` if `key` is cached, `:error` otherwise.
  """
  @spec lookup(key()) :: {:ok, term()} | :error
  def lookup(key) do
    case :ets.lookup(@table, key) do
      [{^key, value}] -> {:ok, value}
      [] -> :error
    end
  end

  @doc """
  Store `value` under `key`.
  """
  @spec put(key(), term()) :: :ok
  def put(key, value) do
    true = :ets.insert(@table, {key, value})
    :ok
  end

  @doc """
  Remove every entry.
  """
  @spec clear() :: :ok
  def clear do
    true = :ets.delete_all_objects(@table)
    :ok
  end

  defp store({:ok, value} = result, key) do
    put(key, value)
    result
  end

  defp store(result, _key) do
    result
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    {:ok, nil}
  end
end
