defmodule Tezex.Crypto.PublicKey do
  @moduledoc """
  Holds public key data.

  Parameters:
  - `:point` [%Point]: public key point data;
  - `:curve` [%Curve]: public key curve information.
  """
  defstruct [:point, :curve]

  alias Tezex.Crypto.{Point, Curve}

  @type t :: %__MODULE__{
          point: Point.t(),
          curve: Curve.t()
        }
end
