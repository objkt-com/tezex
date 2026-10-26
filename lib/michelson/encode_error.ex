defmodule Tezex.Michelson.EncodeError do
  @moduledoc """
  A value that doesn't fit its Michelson type, returned by `Tezex.Michelson.encode/2`
  and raised by `Tezex.Michelson.encode!/2`.

  - `reason`: what went wrong, see `t:reason/0`.
  - `path`: where in the value, root first. A segment is a field or branch name
    (string), a tuple or list position (integer), `:left` / `:right` for an `or`
    branch without a name, `{:key, k}` for a map key or set element, and
    `{:value, k}` for the value under map key `k`.
  - `value`: the value that was rejected (`nil` for a missing field).
  - `expected`: what would have been accepted there.
  """

  @type reason() ::
          :invalid_value
          | :missing_field
          | :unknown_field
          | :duplicate_field
          | :unknown_branch
          | :ambiguous_branch
          | :duplicate_key
          | :not_comparable
          | :not_passable
          | :unsupported_type

  @type segment() ::
          String.t() | non_neg_integer() | :left | :right | {:key, term()} | {:value, term()}

  @type t() :: %__MODULE__{
          reason: reason(),
          path: [segment()],
          value: term(),
          expected: String.t()
        }

  defexception [:reason, :path, :value, :expected]

  @impl true
  def message(%__MODULE__{reason: :missing_field} = error) do
    "missing_field at #{format_path(error.path)}: expected #{error.expected}"
  end

  def message(%__MODULE__{} = error) do
    "#{error.reason} at #{format_path(error.path)}: expected #{error.expected}, " <>
      "got: #{inspect(error.value)}"
  end

  defp format_path([]), do: "the root"
  defp format_path([segment | rest]), do: Enum.reduce(rest, label(segment), &join/2)

  defp join(segment, acc) when is_integer(segment) or is_tuple(segment), do: acc <> label(segment)
  defp join(segment, acc), do: acc <> "." <> label(segment)

  defp label(segment) when is_binary(segment), do: segment
  defp label(segment) when is_atom(segment), do: Atom.to_string(segment)
  defp label(segment) when is_integer(segment), do: "[#{segment}]"
  defp label({:key, key}), do: "{key #{inspect(key)}}"
  defp label({:value, key}), do: "[#{inspect(key)}]"
end
