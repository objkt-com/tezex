defmodule Tezex.Michelson.Comparable do
  @moduledoc false

  # Sort keys that order Micheline values the way the protocol compares them
  # (script_comparable.ml), so that Elixir's term order sorts map and set
  # literals. Values must already be valid: they come out of
  # `Tezex.Michelson.encode/2`.

  alias Tezex.Crypto.ECDSA
  alias Tezex.Crypto.KnownCurves
  alias Tezex.Michelson
  alias Tezex.Michelson.Base58

  @spec comparable?(map()) :: boolean()
  def comparable?(%{"prim" => "unit"}), do: true
  def comparable?(%{"prim" => "never"}), do: true
  def comparable?(%{"prim" => "bool"}), do: true
  def comparable?(%{"prim" => "int"}), do: true
  def comparable?(%{"prim" => "nat"}), do: true
  def comparable?(%{"prim" => "string"}), do: true
  def comparable?(%{"prim" => "chain_id"}), do: true
  def comparable?(%{"prim" => "bytes"}), do: true
  def comparable?(%{"prim" => "mutez"}), do: true
  def comparable?(%{"prim" => "key_hash"}), do: true
  def comparable?(%{"prim" => "key"}), do: true
  def comparable?(%{"prim" => "signature"}), do: true
  def comparable?(%{"prim" => "timestamp"}), do: true
  def comparable?(%{"prim" => "address"}), do: true
  def comparable?(%{"prim" => "option", "args" => [inner]}), do: comparable?(inner)
  def comparable?(%{"prim" => "or", "args" => args}), do: Enum.all?(args, &comparable?/1)
  def comparable?(%{"prim" => "pair", "args" => args}), do: Enum.all?(args, &comparable?/1)
  def comparable?(_type), do: false

  @spec sort_key(map(), Michelson.micheline()) :: term()
  def sort_key(%{"prim" => "unit"}, _value) do
    0
  end

  def sort_key(%{"prim" => "bool"}, %{"prim" => "False"}) do
    0
  end

  def sort_key(%{"prim" => "bool"}, %{"prim" => "True"}) do
    1
  end

  def sort_key(%{"prim" => "int"}, %{"int" => int}) do
    String.to_integer(int)
  end

  def sort_key(%{"prim" => "nat"}, %{"int" => int}) do
    String.to_integer(int)
  end

  def sort_key(%{"prim" => "mutez"}, %{"int" => int}) do
    String.to_integer(int)
  end

  def sort_key(%{"prim" => "string"}, %{"string" => string}) do
    string
  end

  def sort_key(%{"prim" => "bytes"}, %{"bytes" => hex}) do
    Base.decode16!(hex, case: :lower)
  end

  def sort_key(%{"prim" => "timestamp"}, %{"string" => rfc3339}) do
    {:ok, datetime, _offset} = DateTime.from_iso8601(rfc3339)
    DateTime.to_unix(datetime)
  end

  def sort_key(%{"prim" => "key_hash"}, %{"string" => key_hash}) do
    {:ok, decoded} = Base58.key_hash(key_hash)
    decoded
  end

  def sort_key(%{"prim" => "key"}, %{"string" => key}) do
    {:ok, decoded} = Base58.key(key)
    uncompress_p256(decoded)
  end

  def sort_key(%{"prim" => "signature"}, %{"string" => signature}) do
    {:ok, decoded} = Base58.signature(signature)
    decoded
  end

  def sort_key(%{"prim" => "chain_id"}, %{"string" => chain_id}) do
    {:ok, decoded} = Base58.chain_id(chain_id)
    decoded
  end

  def sort_key(%{"prim" => "address"}, %{"string" => address}) do
    {:ok, decoded} = Base58.address(address)
    decoded
  end

  def sort_key(%{"prim" => "option"}, %{"prim" => "None"}) do
    {0, nil}
  end

  def sort_key(%{"prim" => "option", "args" => [inner]}, %{"prim" => "Some", "args" => [value]}) do
    {1, sort_key(inner, value)}
  end

  def sort_key(%{"prim" => "or", "args" => [left, _]}, %{"prim" => "Left", "args" => [value]}) do
    {0, sort_key(left, value)}
  end

  def sort_key(%{"prim" => "or", "args" => [_, right]}, %{"prim" => "Right", "args" => [value]}) do
    {1, sort_key(right, value)}
  end

  def sort_key(%{"prim" => "pair"} = type, %{"prim" => "Pair", "args" => [left, right]}) do
    [left_type, right_type] = Michelson.pair_args(type)
    {sort_key(left_type, left), sort_key(right_type, right)}
  end

  # p256 keys compare by their raw uncompressed point, x then y, not by the
  # compressed bytes they're written in (Hacl.P256.compare, src/lib_hacl/hacl.ml).
  defp uncompress_p256({2, compressed}) do
    curve = KnownCurves.get_curve_by_name(:prime256v1)
    %{x: x, y: y} = ECDSA.decode_point(compressed, curve)
    {2, <<x::unsigned-size(256), y::unsigned-size(256)>>}
  end

  defp uncompress_p256(key) do
    key
  end
end
