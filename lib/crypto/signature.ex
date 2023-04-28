defmodule Tezex.Crypto.Signature do
  @moduledoc """
  Holds signature data.

  Parameters:
  - `:r` [integer]: first signature number;
  - `:s` [integer]: second signature number.
  """
  defstruct [:r, :s]
end
