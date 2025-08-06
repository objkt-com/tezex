defmodule Tezex.Crypto.Point do
  @moduledoc """
  Holds point data. Is usually handled internally by the library and serves only as detailed information to the end-user.

  Parameters:
  - `:x` [`t:non_neg_integer/0`]: first point coordinate;
  - `:y` [`t:non_neg_integer/0`]: first point coordinate;
  - `:z` [`t:non_neg_integer/0`]: first point coordinate (used only in Jacobian coordinates);
  """
  defstruct [:x, :y, z: 0]

  @type t :: %__MODULE__{
          x: non_neg_integer(),
          y: non_neg_integer(),
          z: non_neg_integer()
        }

  @spec is_at_infinity?(__MODULE__.t()) :: boolean()
  def is_at_infinity?(p) do
    p.y == 0
  end
end
