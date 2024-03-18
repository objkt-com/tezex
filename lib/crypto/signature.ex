defmodule Tezex.Crypto.Signature do
  @moduledoc """
  Holds signature data.

  Parameters:
  - `:r` [`t:pos_integer/0`]: first signature number;
  - `:s` [`t:pos_integer/0`]: second signature number.
  """
  defstruct [:r, :s]

  @type t :: %__MODULE__{
          r: pos_integer,
          s: pos_integer
        }
end
