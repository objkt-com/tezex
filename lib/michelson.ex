defmodule Tezex.Michelson do
  @moduledoc """
  Build the Micheline value of a contract call from an Elixir term and the
  Michelson type it must have.

  `encode/2` takes the type as Micheline JSON, as the node returns it (see
  `Tezex.Rpc.entrypoint/3`), and returns Micheline JSON to send as a
  transaction's `parameters.value`. `schema/1` shows the term `encode/2`
  expects for a type.

  `Tezex.Micheline` only serializes trees and doesn't know what they mean. The
  rules here are Michelson's: `pair a b c` is `pair a (pair b c)`, `mutez` is a
  64-bit signed integer, map keys are sorted in the protocol's order.

  ## Values

  | type                  | Elixir value                                                                                                                              |
  | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
  | `unit`                | `:unit`                                                                                                                                   |
  | `bool`                | `true`, `false`                                                                                                                           |
  | `int`                 | an integer                                                                                                                                |
  | `nat`                 | an integer >= 0                                                                                                                           |
  | `mutez`               | an integer from 0 to 2^63 - 1                                                                                                             |
  | `string`              | a string of printable ASCII (codes 32 to 126) and newlines                                                                                |
  | `bytes`               | a binary of raw bytes, not hex: `<<5, 1>>`                                                                                                |
  | `bls12_381_*`         | a binary of raw bytes, not hex: `<<5, 1>>`                                                                                                |
  | `chest`               | a binary of raw bytes, not hex: `<<5, 1>>`                                                                                                |
  | `chest_key`           | a binary of raw bytes, not hex: `<<5, 1>>`                                                                                                |
  | `sapling_transaction` | a binary of raw bytes, not hex: `<<5, 1>>`                                                                                                |
  | `address`, `contract` | a base58 string, optionally `"KT1…%entrypoint"` (`%default` is forbidden)                                                                 |
  | `key_hash`            | a base58 string                                                                                                                           |
  | `key`                 | a base58 string                                                                                                                           |
  | `signature`           | a base58 string                                                                                                                           |
  | `chain_id`            | a base58 string                                                                                                                           |
  | `timestamp`           | a `DateTime` with whole seconds                                                                                                           |
  | `list`                | a list                                                                                                                                    |
  | `set`                 | a list or a `MapSet`                                                                                                                      |
  | `map`, `big_map`      | a map                                                                                                                                     |
  | `lambda`              | the code as Micheline JSON, passed through as is                                                                                          |
  | `sapling_state`       | `[]`, an empty state                                                                                                                      |
  | `option`              | `nil` (or a missing field) for `None`, any other value `v` for `Some v`; `{:some, nil}` for `Some None` when the type inside is an option |
  | `pair`                | a map when every field has a name and no two share one, a tuple otherwise                                                                 |
  | `or`                  | `{name, value}`, or `name` for a `unit` branch; `{:left, value}` / `{:right, value}` for a branch without a name                          |

  `never`, `operation` and `ticket` take no value.

  `encode/2` checks a value's format, not its cryptographic validity: it doesn't
  check that a key or signature is a point on its curve, or that `bls12_381_*`
  bytes are a valid point. The node checks those and rejects the operation.

  Names are `%` annotations. An `option`'s name can be on the option
  (`option %expiry nat`) or on the type inside (`option (nat %expiry)`).

  ### pair

  Fields are counted after flattening the nested pairs that have no name, so
  `pair (nat %a) (pair (nat %b) (nat %c))` is `%{a: 1, b: 2, c: 3}`. Keys can be
  atoms or strings.

  A tuple can be written nested or flat on the right, since `pair a b c` is the
  same type as `pair a (pair b c)`: `{1, 2, 3}` or `{1, {2, 3}}`. The output is
  always nested: `Pair 1 (Pair 2 3)`.

  ### or

  Names are found through the nested `or`s that have no name: in
  `or (or (nat %a) (nat %b)) nat`, `{:a, 1}` works. `:left` / `:right` pick a
  branch without a name. It's an error when they could also mean a branch named
  `%left` / `%right`.

  ### map, set

  Elements are sorted in the protocol's order for the key type, and two keys
  that encode to the same value are an error.

  ## Examples

      iex> type = %{
      ...>   "prim" => "pair",
      ...>   "args" => [
      ...>     %{"prim" => "address", "annots" => ["%holder"]},
      ...>     %{"prim" => "nat", "annots" => ["%amount"]}
      ...>   ]
      ...> }
      iex> encode(type, %{holder: "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew", amount: 5})
      {:ok, %{"prim" => "Pair", "args" => [%{"string" => "tz1ZW1ZSN4ruXYc3nCon8EaTXp1t3tKWb9Ew"}, %{"int" => "5"}]}}
      iex> schema(type)
      %{"holder" => :address, "amount" => :nat}

      iex> type = %{
      ...>   "prim" => "or",
      ...>   "args" => [
      ...>     %{"prim" => "unit", "annots" => ["%tez"]},
      ...>     %{"prim" => "address", "annots" => ["%fa12"]}
      ...>   ]
      ...> }
      iex> encode(type, :tez)
      {:ok, %{"prim" => "Left", "args" => [%{"prim" => "Unit"}]}}
      iex> schema(type)
      {:or, ["tez", {"fa12", :address}]}

      iex> {:error, error} = encode(%{"prim" => "nat"}, -1)
      iex> Exception.message(error)
      "invalid_value at the root: expected an integer >= 0, got: -1"
  """

  alias Tezex.Michelson.Base58
  alias Tezex.Michelson.Comparable
  alias Tezex.Michelson.EncodeError

  @typedoc "Micheline JSON, decoded: a node map or a sequence."
  @type micheline() :: map() | [micheline()]

  @typedoc """
  What `schema/1` returns:

    * a scalar: its type name, `:nat`
    * a `pair`: a map of field name to schema when every field has a unique
      name, else a tuple of schemas
    * an `or`: `{:or, branches}`, where a branch is one of:
      * `name`: a named `unit` branch
      * `{name, schema}`: a named branch
      * `:left` / `:right`: an unnamed `unit` branch
      * `{:left | :right, schema}`: an unnamed branch
    * `{:option, schema}`, `{:list, schema}`, `{:set, schema}`,
      `{:contract, parameter}`, `{:ticket, schema}`
    * `{:map, key, value}`, `{:big_map, key, value}`, `{:lambda, arg, return}`
    * `{:unsupported, prim}`: a type tezex doesn't know
  """
  @type schema() :: atom() | String.t() | tuple() | %{String.t() => schema()}

  @max_mutez 2 ** 63 - 1
  @bytes_types ~w(bytes bls12_381_g1 bls12_381_g2 bls12_381_fr chest chest_key sapling_transaction)
  @base58_types ~w(address contract key_hash key signature chain_id)
  @scalar_schemas %{
    "unit" => :unit,
    "bool" => :bool,
    "int" => :int,
    "nat" => :nat,
    "mutez" => :mutez,
    "string" => :string,
    "bytes" => :bytes,
    "address" => :address,
    "key_hash" => :key_hash,
    "key" => :key,
    "signature" => :signature,
    "chain_id" => :chain_id,
    "timestamp" => :timestamp,
    "never" => :never,
    "operation" => :operation,
    "bls12_381_g1" => :bls12_381_g1,
    "bls12_381_g2" => :bls12_381_g2,
    "bls12_381_fr" => :bls12_381_fr,
    "chest" => :chest,
    "chest_key" => :chest_key,
    "sapling_transaction" => :sapling_transaction,
    "sapling_state" => :sapling_state
  }

  @doc """
  Encodes `value` as Micheline JSON of Michelson type `type`.

  Returns `{:error, %Tezex.Michelson.EncodeError{}}` with the path to the value
  that doesn't fit.
  """
  @spec encode(map(), term()) :: {:ok, micheline()} | {:error, EncodeError.t()}
  def encode(type, value) do
    do_encode(type, value, [])
  end

  @doc """
  Same as `encode/2` but returns the Micheline directly, and raises
  `Tezex.Michelson.EncodeError` when the value doesn't fit.
  """
  @spec encode!(map(), term()) :: micheline()
  def encode!(type, value) do
    case encode(type, value) do
      {:ok, micheline} -> micheline
      {:error, error} -> raise error
    end
  end

  @doc """
  Shows the term `encode/2` expects for `type`, see `t:schema/0`.

  Field and branch names are strings: they come from the contract, and atoms
  are never garbage collected.
  """
  @spec schema(map()) :: schema()
  def schema(%{"prim" => "pair", "args" => [_, _ | _]} = type) do
    case record_names(type) do
      {:ok, _names} -> type |> record_leaves() |> Map.new(&{field_name(&1), schema(&1)})
      :error -> type |> comb() |> Enum.map(&schema/1) |> List.to_tuple()
    end
  end

  def schema(%{"prim" => "or", "args" => [_, _]} = type) do
    {:or, or_entries(type)}
  end

  def schema(%{"prim" => prim, "args" => [inner]})
      when prim in ~w(option list set contract ticket) do
    {String.to_existing_atom(prim), schema(inner)}
  end

  def schema(%{"prim" => prim, "args" => [left, right]}) when prim in ~w(map big_map lambda) do
    {String.to_existing_atom(prim), schema(left), schema(right)}
  end

  def schema(%{"prim" => prim}) do
    case Map.fetch(@scalar_schemas, prim) do
      {:ok, schema} -> schema
      :error -> {:unsupported, prim}
    end
  end

  @doc false
  # `pair a b c` is `pair a (pair b c)`: the args of a pair as a binary pair.
  @spec pair_args(map()) :: [map()]
  def pair_args(%{"args" => [left, right]}), do: [left, right]
  def pair_args(%{"args" => [left | rest]}), do: [left, %{"prim" => "pair", "args" => rest}]

  defp do_encode(%{"prim" => "unit"}, :unit, _path) do
    {:ok, %{"prim" => "Unit"}}
  end

  defp do_encode(%{"prim" => "bool"}, value, _path) when is_boolean(value) do
    prim = if value, do: "True", else: "False"
    {:ok, %{"prim" => prim}}
  end

  defp do_encode(%{"prim" => "int"}, value, _path) when is_integer(value) do
    {:ok, %{"int" => Integer.to_string(value)}}
  end

  defp do_encode(%{"prim" => "nat"}, value, _path) when is_integer(value) and value >= 0 do
    {:ok, %{"int" => Integer.to_string(value)}}
  end

  defp do_encode(%{"prim" => "mutez"}, v, _path) when is_integer(v) and v in 0..@max_mutez do
    {:ok, %{"int" => Integer.to_string(v)}}
  end

  defp do_encode(%{"prim" => "string"} = type, value, path) when is_binary(value) do
    if michelson_string?(value) do
      {:ok, %{"string" => value}}
    else
      invalid(type, value, path)
    end
  end

  defp do_encode(%{"prim" => prim}, v, _path) when prim in @bytes_types and is_binary(v) do
    {:ok, %{"bytes" => Base.encode16(v, case: :lower)}}
  end

  defp do_encode(%{"prim" => prim} = type, v, path) when prim in @base58_types and is_binary(v) do
    case Base58.decode(prim, v) do
      {:ok, _decoded} -> {:ok, %{"string" => v}}
      :error -> invalid(type, v, path)
    end
  end

  defp do_encode(%{"prim" => "timestamp"}, %DateTime{microsecond: {0, _}} = value, _path) do
    utc = value |> DateTime.to_unix() |> DateTime.from_unix!()
    {:ok, %{"string" => DateTime.to_iso8601(utc)}}
  end

  defp do_encode(%{"prim" => "lambda"}, value, _path)
       when is_list(value) or (is_map(value) and not is_struct(value)) do
    {:ok, value}
  end

  defp do_encode(%{"prim" => "sapling_state"}, [], _path) do
    {:ok, []}
  end

  defp do_encode(%{"prim" => "option", "args" => [_]}, nil, _path) do
    {:ok, %{"prim" => "None"}}
  end

  defp do_encode(
         %{"prim" => "option", "args" => [%{"prim" => "option"} = inner]},
         {:some, value},
         path
       ) do
    some(inner, value, path)
  end

  defp do_encode(%{"prim" => "option", "args" => [inner]}, value, path) do
    some(inner, value, path)
  end

  defp do_encode(%{"prim" => "list", "args" => [inner]}, value, path) when is_list(value) do
    value
    |> Enum.with_index()
    |> map_while_ok(fn {item, index} -> do_encode(inner, item, [index | path]) end)
  end

  defp do_encode(%{"prim" => "set", "args" => [inner]}, value, path)
       when is_list(value) or is_struct(value, MapSet) do
    items = Enum.to_list(value)

    with :ok <- check_comparable(inner, value, path),
         {:ok, encoded} <- map_while_ok(items, &do_encode(inner, &1, [{:key, &1} | path])) do
      encoded
      |> Enum.zip_with(items, fn element, item -> {element, element, item} end)
      |> sort_unique(inner, path)
    end
  end

  defp do_encode(%{"prim" => prim, "args" => [key_type, value_type]}, value, path)
       when prim in ~w(map big_map) and is_map(value) and not is_struct(value) do
    with :ok <- check_comparable(key_type, value, path),
         {:ok, entries} <- map_while_ok(value, &encode_entry(key_type, value_type, &1, path)) do
      sort_unique(entries, key_type, path)
    end
  end

  defp do_encode(%{"prim" => "pair", "args" => [_, _ | _]} = type, value, path) do
    case record_names(type) do
      {:ok, names} -> encode_record(type, value, names, path)
      :error -> encode_tuple(type, value, path)
    end
  end

  defp do_encode(%{"prim" => "or", "args" => [_, _]} = type, value, path) do
    with {:ok, tag, inner} <- branch_tag(type, value, path),
         {:ok, sides, branch_type, segment} <- find_branch(type, tag, value, path),
         {:ok, inner} <- branch_value(branch_type, inner, tag, value, path),
         {:ok, encoded} <- do_encode(branch_type, inner, [segment | path]) do
      {:ok, List.foldr(sides, encoded, &%{"prim" => side_prim(&1), "args" => [&2]})}
    end
  end

  defp do_encode(%{"prim" => prim} = type, value, path) when prim in ~w(operation ticket) do
    error(:not_passable, path, value, expected(type))
  end

  defp do_encode(type, value, path) do
    invalid(type, value, path)
  end

  defp some(type, value, path) do
    with {:ok, encoded} <- do_encode(type, value, path) do
      {:ok, %{"prim" => "Some", "args" => [encoded]}}
    end
  end

  defp michelson_string?(<<>>) do
    true
  end

  defp michelson_string?(<<c, rest::binary>>) when c == ?\n or c in 32..126 do
    michelson_string?(rest)
  end

  defp michelson_string?(_string) do
    false
  end

  ## map and set

  defp encode_entry(key_type, value_type, {key, value}, path) do
    with {:ok, encoded_key} <- do_encode(key_type, key, [{:key, key} | path]),
         {:ok, encoded_value} <- do_encode(value_type, value, [{:value, key} | path]) do
      {:ok, {encoded_key, %{"prim" => "Elt", "args" => [encoded_key, encoded_value]}, key}}
    end
  end

  defp check_comparable(type, value, path) do
    if Comparable.comparable?(type) do
      :ok
    else
      error(:not_comparable, path, value, "a comparable key type, got type #{inspect(type)}")
    end
  end

  # `entries` are `{encoded_key, output_item, original_key}`.
  defp sort_unique(entries, key_type, path) do
    entries
    |> Enum.map(fn {key, item, original} ->
      {Comparable.sort_key(key_type, key), item, original}
    end)
    |> Enum.sort_by(&elem(&1, 0))
    |> unique_items([], path)
  end

  # Once sorted, two equal keys are next to each other.
  defp unique_items([{key, _, first}, {key, _, second} | _rest], _acc, path) do
    expected = "a key different from #{inspect(first)}"
    error(:duplicate_key, [{:key, second} | path], second, expected)
  end

  defp unique_items([{_key, item, _original} | rest], acc, path) do
    unique_items(rest, [item | acc], path)
  end

  defp unique_items([], acc, _path) do
    {:ok, Enum.reverse(acc)}
  end

  ## pair

  # A pair is a record when every field has a name and no two share one.
  defp record_names(type) do
    names = type |> record_leaves() |> Enum.map(&field_name/1)

    if Enum.all?(names) and Enum.uniq(names) == names do
      {:ok, names}
    else
      :error
    end
  end

  # The fields of a record: nested pairs without a name are flattened.
  defp record_leaves(type) do
    type
    |> pair_args()
    |> Enum.flat_map(fn arg ->
      if unnamed_pair?(arg) do
        record_leaves(arg)
      else
        [arg]
      end
    end)
  end

  defp encode_record(type, value, names, path) when is_map(value) and not is_struct(value) do
    with {:ok, fields} <- record_fields(value, names, path) do
      encode_record_node(type, fields, path)
    end
  end

  defp encode_record(type, value, _names, path) do
    invalid(type, value, path)
  end

  # The value's keys by name, as strings.
  defp record_fields(value, names, path) do
    Enum.reduce_while(value, {:ok, %{}}, fn {key, field_value}, {:ok, fields} ->
      name = key_name(key)

      cond do
        name not in names ->
          expected = "one of the fields " <> Enum.join(names, ", ")
          {:halt, error(:unknown_field, [name || inspect(key) | path], field_value, expected)}

        Map.has_key?(fields, name) ->
          expected = "each field once, as an atom or a string key"
          {:halt, error(:duplicate_field, [name | path], field_value, expected)}

        true ->
          {:cont, {:ok, Map.put(fields, name, field_value)}}
      end
    end)
  end

  defp key_name(key) when is_atom(key), do: Atom.to_string(key)
  defp key_name(key) when is_binary(key), do: key
  defp key_name(_key), do: nil

  defp encode_record_node(type, fields, path) do
    with {:ok, args} <- map_while_ok(pair_args(type), &encode_record_arg(&1, fields, path)) do
      {:ok, %{"prim" => "Pair", "args" => args}}
    end
  end

  defp encode_record_arg(type, fields, path) do
    if unnamed_pair?(type) do
      encode_record_node(type, fields, path)
    else
      encode_field(type, field_name(type), fields, path)
    end
  end

  defp encode_field(type, name, fields, path) do
    case Map.fetch(fields, name) do
      {:ok, value} -> do_encode(type, value, [name | path])
      :error -> missing_field(type, name, path)
    end
  end

  defp missing_field(%{"prim" => "option"}, _name, _path) do
    {:ok, %{"prim" => "None"}}
  end

  defp missing_field(type, name, path) do
    error(:missing_field, [name | path], nil, expected(type))
  end

  defp encode_tuple(type, value, path) when is_tuple(value) do
    if tuple_size(value) in 2..length(comb(type)) do
      encode_comb(type, Tuple.to_list(value), 0, path)
    else
      invalid(type, value, path)
    end
  end

  defp encode_tuple(type, value, path) do
    invalid(type, value, path)
  end

  defp encode_comb(type, [value | rest], index, path) do
    [left, right] = pair_args(type)

    with {:ok, encoded_left} <- do_encode(left, value, [index | path]),
         {:ok, encoded_right} <- encode_comb_rest(right, rest, index + 1, path) do
      {:ok, %{"prim" => "Pair", "args" => [encoded_left, encoded_right]}}
    end
  end

  # More than one value left: the tuple is flat, `encode_tuple/3` checked that
  # `type` is the rest of the comb.
  defp encode_comb_rest(type, [value], index, path), do: do_encode(type, value, [index | path])
  defp encode_comb_rest(type, values, index, path), do: encode_comb(type, values, index, path)

  # The fields of a pair as a tuple: flattened on the right, through the nested
  # pairs that have no name.
  defp comb(type) do
    [left, right] = pair_args(type)

    if unnamed_pair?(right) do
      [left | comb(right)]
    else
      [left, right]
    end
  end

  defp unnamed_pair?(%{"prim" => "pair", "args" => [_, _ | _]} = type) do
    field_name(type) == nil
  end

  defp unnamed_pair?(_type) do
    false
  end

  ## or

  defp branch_tag(_type, {tag, value}, _path)
       when is_binary(tag) or (is_atom(tag) and tag not in [nil, true, false]) do
    {:ok, to_string(tag), {:value, value}}
  end

  defp branch_tag(_type, tag, _path)
       when is_binary(tag) or (is_atom(tag) and tag not in [nil, true, false]) do
    {:ok, to_string(tag), :bare}
  end

  defp branch_tag(type, value, path) do
    invalid(type, value, path)
  end

  defp find_branch(type, tag, value, path) do
    branches = named_branches(type, tag) ++ positional_branch(type, tag)

    case branches do
      [{sides, branch_type, segment}] ->
        {:ok, sides, branch_type, segment}

      [] ->
        error(:unknown_branch, path, value, expected(type))

      [_, _ | _] ->
        expected = "a branch name that matches one branch, #{inspect(tag)} matches several"
        error(:ambiguous_branch, path, value, expected)
    end
  end

  # The branches named `tag`, found through the nested `or`s that have no name.
  defp named_branches(%{"args" => [left, right]}, tag) do
    Enum.flat_map([left: left, right: right], fn {side, child} ->
      named_branch(side, child, field_name(child), tag)
    end)
  end

  defp named_branch(side, child, tag, tag) do
    [{[side], child, tag}]
  end

  defp named_branch(side, %{"prim" => "or", "args" => [_, _]} = child, nil, tag) do
    for {sides, branch_type, segment} <- named_branches(child, tag) do
      {[side | sides], branch_type, segment}
    end
  end

  defp named_branch(_side, _child, _name, _tag) do
    []
  end

  defp positional_branch(%{"args" => [left, _right]}, "left"), do: positional(:left, left)
  defp positional_branch(%{"args" => [_left, right]}, "right"), do: positional(:right, right)
  defp positional_branch(_type, _tag), do: []

  defp positional(side, child) do
    if field_name(child) == nil, do: [{[side], child, side}], else: []
  end

  defp branch_value(_branch_type, {:value, value}, _tag, _or_value, _path) do
    {:ok, value}
  end

  defp branch_value(%{"prim" => "unit"}, :bare, _tag, _or_value, _path) do
    {:ok, :unit}
  end

  defp branch_value(_branch_type, :bare, tag, or_value, path) do
    error(:invalid_value, path, or_value, "{#{tag}, value}, #{tag} isn't a unit branch")
  end

  defp side_prim(:left), do: "Left"
  defp side_prim(:right), do: "Right"

  # Branch labels for `expected/1`.
  defp branch_labels(%{"args" => [left, right]} = type) do
    positional =
      for {side, child} <- [left: left, right: right], field_name(child) == nil do
        inspect(side)
      end

    named_labels(type) ++ positional
  end

  defp named_labels(%{"args" => [left, right]}) do
    Enum.flat_map([left, right], fn child ->
      case {field_name(child), child} do
        {nil, %{"prim" => "or", "args" => [_, _]}} -> named_labels(child)
        {nil, _child} -> []
        {name, _child} -> [name]
      end
    end)
  end

  defp or_entries(%{"args" => [left, right]}) do
    Enum.flat_map([left: left, right: right], fn {side, child} ->
      or_entry(side, child, field_name(child))
    end)
  end

  defp or_entry(_side, child, name) when is_binary(name) do
    [named_entry(name, child)]
  end

  defp or_entry(side, %{"prim" => "or", "args" => [_, _]} = child, nil) do
    named = for name <- named_labels(child), do: named_entry(name, find_named(child, name))

    if unnamed_leaf?(child) do
      named ++ [{side, schema(child)}]
    else
      named
    end
  end

  defp or_entry(side, %{"prim" => "unit"}, nil) do
    [side]
  end

  defp or_entry(side, child, nil) do
    [{side, schema(child)}]
  end

  defp named_entry(name, %{"prim" => "unit"}), do: name
  defp named_entry(name, child), do: {name, schema(child)}

  defp find_named(type, name) do
    [{_sides, branch_type, _segment} | _] = named_branches(type, name)
    branch_type
  end

  # Whether some branch of `type` can only be reached with `:left` / `:right`.
  defp unnamed_leaf?(%{"args" => [left, right]}) do
    Enum.any?([left, right], fn child ->
      case {field_name(child), child} do
        {nil, %{"prim" => "or", "args" => [_, _]}} -> unnamed_leaf?(child)
        {nil, _child} -> true
        {_name, _child} -> false
      end
    end)
  end

  ## names

  # The `%` annotation of a field or branch. An option's name can be on the
  # type inside it: `option (nat %expiry)`.
  defp field_name(type) do
    case own_field_name(type) do
      nil -> inner_field_name(type)
      name -> name
    end
  end

  defp own_field_name(%{"annots" => annots}) do
    Enum.find_value(annots, fn
      "%" <> name when name != "" -> name
      _annot -> nil
    end)
  end

  defp own_field_name(_type) do
    nil
  end

  defp inner_field_name(%{"prim" => "option", "args" => [inner]}), do: own_field_name(inner)
  defp inner_field_name(_type), do: nil

  ## errors

  defp invalid(type, value, path) do
    case expected(type) do
      nil -> error(:unsupported_type, path, value, "a supported type, got type #{inspect(type)}")
      expected -> error(:invalid_value, path, value, expected)
    end
  end

  defp error(reason, path, value, expected) do
    {:error,
     %EncodeError{reason: reason, path: Enum.reverse(path), value: value, expected: expected}}
  end

  defp expected(%{"prim" => "unit"}), do: ":unit"
  defp expected(%{"prim" => "bool"}), do: "true or false"
  defp expected(%{"prim" => "int"}), do: "an integer"
  defp expected(%{"prim" => "nat"}), do: "an integer >= 0"
  defp expected(%{"prim" => "mutez"}), do: "an integer from 0 to 2^63 - 1"
  defp expected(%{"prim" => "string"}), do: "a string of printable ASCII and newlines"
  defp expected(%{"prim" => prim}) when prim in @bytes_types, do: "a binary of raw bytes"
  defp expected(%{"prim" => "address"}), do: "a base58 address"
  defp expected(%{"prim" => "contract"}), do: "a base58 address"
  defp expected(%{"prim" => "key_hash"}), do: "a base58 tz1, tz2, tz3 or tz4 key hash"
  defp expected(%{"prim" => "key"}), do: "a base58 edpk, sppk, p2pk or BLpk public key"
  defp expected(%{"prim" => "signature"}), do: "a base58 signature"
  defp expected(%{"prim" => "chain_id"}), do: "a base58 chain id"
  defp expected(%{"prim" => "timestamp"}), do: "a DateTime with whole seconds"
  defp expected(%{"prim" => "lambda"}), do: "Micheline code, a list or a map"
  defp expected(%{"prim" => "sapling_state"}), do: "[], an empty sapling state"
  defp expected(%{"prim" => "never"}), do: "nothing, never has no values"
  defp expected(%{"prim" => "operation"}), do: "nothing, an operation isn't passable"
  defp expected(%{"prim" => "ticket"}), do: "nothing, tickets are sent with Transfer_ticket"
  defp expected(%{"prim" => "option", "args" => [inner]}), do: expected_option(expected(inner))
  defp expected(%{"prim" => "list", "args" => [_]}), do: "a list"
  defp expected(%{"prim" => "set", "args" => [_]}), do: "a list or a MapSet"
  defp expected(%{"prim" => "map", "args" => [_, _]}), do: "a map"
  defp expected(%{"prim" => "big_map", "args" => [_, _]}), do: "a map"
  defp expected(%{"prim" => "pair", "args" => [_, _ | _]} = type), do: expected_pair(type)
  defp expected(%{"prim" => "or", "args" => [_, _]} = type), do: expected_or(type)
  defp expected(_type), do: nil

  defp expected_option(nil), do: nil
  defp expected_option(expected), do: expected <> ", or nil"

  defp expected_pair(type) do
    case record_names(type) do
      {:ok, names} -> "a map with the fields " <> Enum.join(names, ", ")
      :error -> "a tuple of 2 to #{length(comb(type))} elements"
    end
  end

  defp expected_or(type) do
    "{branch, value}, or the name of a unit branch, where branch is one of: " <>
      Enum.join(branch_labels(type), ", ")
  end

  ## helpers

  defp map_while_ok(enumerable, fun) do
    enumerable
    |> Enum.reduce_while({:ok, []}, fn item, {:ok, acc} ->
      case fun.(item) do
        {:ok, result} -> {:cont, {:ok, [result | acc]}}
        {:error, _error} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end
  end
end
