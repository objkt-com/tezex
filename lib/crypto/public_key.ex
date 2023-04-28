defmodule Tezex.Crypto.PublicKey do
  @moduledoc """
  Holds public key data.

  Parameters:
  - `:point` [%Point]: public key point data;
  - `:curve` [%Curve]: public key curve information.
  """
  defstruct [:point, :curve]
end
