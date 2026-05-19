defmodule Tezex.Crypto.MathTest do
  use ExUnit.Case, async: true

  alias Tezex.Crypto.Math

  describe "mod_inverse/2" do
    test "returns the modular inverse for positive coprime input" do
      # 5 * 3 = 15 = 1 (mod 7)
      assert {:ok, 3} = Math.mod_inverse(5, 7)
    end

    test "returns the modular inverse for negative coprime input" do
      # -5 ≡ 2 (mod 7), and 2 * 4 = 8 = 1 (mod 7)
      assert {:ok, 4} = Math.mod_inverse(-5, 7)
    end

    test "returns :error for zero" do
      assert {:error, :not_invertible} = Math.mod_inverse(0, 7)
    end

    test "returns :error for non-coprime input" do
      assert {:error, :not_invertible} = Math.mod_inverse(7, 7)
      assert {:error, :not_invertible} = Math.mod_inverse(14, 7)
      assert {:error, :not_invertible} = Math.mod_inverse(6, 9)
    end
  end
end
