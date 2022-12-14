defmodule Tezex.Crypto.Base58Check do
  @moduledoc """
  Base58Check encoding/decoding utils
  """
  alias Base58Check.Base58Zero

  @checksum_length 4

  @doc """
  Prepends `prefix` to `payload`, computes its checksum (double sha256) and encodes in Base58.

  ## Examples
    iex(4)> Tezex.Crypto.Base58Check.encode(<<165, 37, 29, 103, 204, 101, 232, 200, 87, 148, 178, 91, 43, 72, 191, 252, 190, 134, 75, 170>>, <<6, 161, 164>>)
    "tz3bPFa6mGv8m4Ppn7w5KSDyAbEPwbJNpC9p"
  """
  @spec encode(binary(), binary()) :: String.t()
  def encode(payload, prefix) do
    (prefix <> payload)
    |> add_checksum()
    |> Base58Zero.encode()
  end

  @spec add_checksum(binary()) :: binary()
  defp add_checksum(payload) do
    payload
    |> double_sha256()
    |> binary_part(0, @checksum_length)
    |> append(payload)
  end

  @spec append(binary(), binary()) :: binary()
  defp append(data1, data2), do: data2 <> data1

  defp double_sha256(x), do: :crypto.hash(:sha256, :crypto.hash(:sha256, x))
end
