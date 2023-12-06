defmodule Tezex.Micheline do
  @moduledoc """
  Decode Micheline code.
  """
  alias Tezex.Micheline.Zarith

  @kw ~w(
      parameter storage code False Elt Left None Pair Right Some True Unit PACK UNPACK
      BLAKE2B SHA256 SHA512 ABS ADD AMOUNT AND BALANCE CAR CDR CHECK_SIGNATURE COMPARE CONCAT
      CONS CREATE_ACCOUNT CREATE_CONTRACT IMPLICIT_ACCOUNT DIP DROP DUP EDIV EMPTY_MAP EMPTY_SET
      EQ EXEC FAILWITH GE GET GT HASH_KEY IF IF_CONS IF_LEFT IF_NONE INT LAMBDA LE LEFT
      LOOP LSL LSR LT MAP MEM MUL NEG NEQ NIL NONE NOT NOW OR PAIR PUSH RIGHT SIZE
      SOME SOURCE SENDER SELF STEPS_TO_QUOTA SUB SWAP TRANSFER_TOKENS SET_DELEGATE UNIT UPDATE XOR
      ITER LOOP_LEFT ADDRESS CONTRACT ISNAT CAST RENAME bool contract int key key_hash lambda
      list map big_map nat option or pair set signature string bytes mutez timestamp unit
      operation address SLICE DIG DUG EMPTY_BIG_MAP APPLY chain_id CHAIN_ID LEVEL SELF_ADDRESS
      never NEVER UNPAIR VOTING_POWER TOTAL_VOTING_POWER KECCAK SHA3 PAIRING_CHECK bls12_381_g1
      bls12_381_g2 bls12_381_fr sapling_state sapling_transaction SAPLING_EMPTY_STATE SAPLING_VERIFY_UPDATE
      ticket TICKET READ_TICKET SPLIT_TICKET JOIN_TICKETS GET_AND_UPDATE chest chest_key OPEN_CHEST
      VIEW view constant
    )

  @doc """
  Parse a single message from a Micheline packed message.

  ## Examples
      iex> Tezex.Micheline.read_packed("02000000210061010000000574657a6f730100000000010000000b63727970746f6e6f6d6963")
      %{int: 33}

      iex> Tezex.Micheline.read_packed("0200e1d22c")
      %{int: -365_729}
  """
  @spec read_packed(binary) :: map | list(map)
  def read_packed(<<_::binary-size(2), rest::binary>>) do
    {val, _consumed} = hex_to_micheline(rest)
    val
  end

  @doc """
  Parse a Micheline hex string, return a tuple `{result, consumed}` containing
  a list of Micheline objects as maps, and the number of bytes that was consumed in the process.

  ## Examples
      iex> Tezex.Micheline.hex_to_micheline("02000000210061010000000574657a6f730100000000010000000b63727970746f6e6f6d6963")
      {[%{int: -33}, %{string: "tezos"}, %{string: ""}, %{string: "cryptonomic"}], 76}

      iex> Tezex.Micheline.hex_to_micheline("00e1d22c")
      {%{int: -365729}, 8}
  """
  @spec hex_to_micheline(binary) :: {map | list(map), pos_integer}
  # literal int or nat
  def hex_to_micheline("00" <> rest) do
    {result, consumed} = Zarith.consume(rest)
    {result, consumed + 2}
  end

  # literal string
  def hex_to_micheline("01" <> rest) do
    {hex_string, length} = micheline_hex_to_string(rest)

    {%{string: :binary.decode_hex(hex_string)}, length + 2}
  end

  # sequence
  def hex_to_micheline(<<"02", length::binary-size(8), rest::binary>>) do
    length = hex_to_dec(length) * 2

    {xs, consumed} =
      Stream.cycle([nil])
      |> Enum.reduce_while({[], rest, 0}, fn _, {acc, part, consumed} ->
        if consumed < length do
          {content, length} = hex_to_micheline(part)
          <<_consumed::binary-size(length), part::binary>> = part
          {:cont, {[content | acc], part, consumed + length}}
        else
          {:halt, {acc, consumed}}
        end
      end)

    {Enum.reverse(xs), consumed + 8 + 2}
  end

  # primitive / no arg / no annot
  def hex_to_micheline("03" <> rest) do
    {kw, consumed} = code_to_kw(rest)
    {%{prim: kw}, 2 + consumed}
  end

  # primitive / no arg / annot
  def hex_to_micheline("04" <> rest) do
    tot_consumed = 2
    {kw, consumed} = code_to_kw(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {annot, consumed} = micheline_hex_to_string(rest)
    annot = :binary.decode_hex(annot)

    {%{prim: kw, annot: annot}, consumed + tot_consumed}
  end

  # primitive / 1 arg / no annot
  def hex_to_micheline("05" <> rest) do
    tot_consumed = 2

    {kw, consumed} = code_to_kw(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {arg, consumed} = hex_to_micheline(rest)
    tot_consumed = consumed + tot_consumed

    {%{prim: kw, args: [arg]}, tot_consumed}
  end

  # primitive / 1 arg / annot
  def hex_to_micheline("06" <> rest) do
    tot_consumed = 2

    {kw, consumed} = code_to_kw(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {arg, consumed} = hex_to_micheline(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {annot, consumed} = micheline_hex_to_string(rest)
    tot_consumed = consumed + tot_consumed

    {%{prim: kw, args: [arg], annots: decode_annotations(annot)}, tot_consumed}
  end

  # primitive / 2 arg / no annot
  def hex_to_micheline("07" <> rest) do
    tot_consumed = 2

    {kw, consumed} = code_to_kw(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {arg1, consumed} = hex_to_micheline(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {arg2, consumed} = hex_to_micheline(rest)
    tot_consumed = consumed + tot_consumed

    {%{prim: kw, args: [arg1, arg2]}, tot_consumed}
  end

  # primitive / 2 arg / annot
  def hex_to_micheline("08" <> rest) do
    tot_consumed = 2

    {kw, consumed} = code_to_kw(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {arg1, consumed} = hex_to_micheline(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {arg2, consumed} = hex_to_micheline(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {annot, consumed} = micheline_hex_to_string(rest)
    tot_consumed = consumed + tot_consumed

    {%{prim: kw, args: [arg1, arg2], annots: decode_annotations(annot)}, tot_consumed}
  end

  # primitive / N arg / maybe annot
  def hex_to_micheline("09" <> rest) do
    tot_consumed = 2

    {kw, consumed} = code_to_kw(rest)
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    {args, consumed} = hex_to_micheline("02" <> rest)
    # -2 to factor out the "02" we just added
    consumed = consumed - 2
    tot_consumed = consumed + tot_consumed
    <<_consumed::binary-size(consumed), rest::binary>> = rest

    case rest do
      # no annotation to parse
      <<"00000000", _rest::binary>> ->
        {%{prim: kw, args: args}, tot_consumed + 8}

      _ ->
        {annot, consumed} = micheline_hex_to_string(rest)
        tot_consumed = consumed + tot_consumed
        {%{prim: kw, args: args, annots: decode_annotations(annot)}, tot_consumed}
    end
  end

  # raw bytes
  def hex_to_micheline(<<"0a", rest::binary>>) do
    {bytes, length} = micheline_hex_to_string(rest)
    {%{bytes: bytes}, length + 2}
  end

  @spec micheline_hex_to_string(binary) :: {binary, pos_integer}
  def micheline_hex_to_string(<<length::binary-size(8), rest::binary>>) do
    length = hex_to_dec(length) * 2
    <<text::binary-size(length), _rest::binary>> = rest
    {text, length + 8}
  end

  @doc """
  Decode optimized Micheline representation of an address value

  ## Examples
      iex> Tezex.Micheline.decode_optimized_address("00007fc95c97fd368cd9055610ee79e64ff9e0b5285c")
      {:ok, "tz1XHhjLXQuG9rf9n7o1VbgegMkiggy1oktu"}
      iex> Tezex.Micheline.decode_optimized_address("10007fc95c97fd368cd9055610ee79e64ff9e0b5285c")
      {:error, :invalid}
  """
  @spec decode_optimized_address(<<_::_*16>>) :: {:error, :invalid} | {:ok, nonempty_binary()}
  def decode_optimized_address(hex) do
    {prefix, pkh} =
      case :binary.decode_hex(hex) do
        <<0, 0, pkh::binary-size(20)>> -> {<<6, 161, 159>>, pkh}
        <<0, 1, pkh::binary-size(20)>> -> {<<6, 161, 161>>, pkh}
        <<0, 2, pkh::binary-size(20)>> -> {<<6, 161, 164>>, pkh}
        <<1, pkh::binary-size(20), 0>> -> {<<2, 90, 121>>, pkh}
        _ -> {:error, :invalid}
      end

    case {prefix, pkh} do
      {:error, :invalid} -> {:error, :invalid}
      {prefix, pkh} -> {:ok, Tezex.Crypto.Base58Check.encode(pkh, prefix)}
    end
  end

  defp code_to_kw(code) when is_integer(code) do
    {Enum.at(@kw, code), 2}
  end

  defp code_to_kw(<<code::binary-size(2), _rest::binary>>) when is_binary(code) do
    {d, _} = Integer.parse(code, 16)
    code_to_kw(d)
  end

  defp decode_annotations(annots_hex) do
    annots_hex
    |> :binary.decode_hex()
    |> String.split(" ")
  end

  defp hex_to_dec(hex) do
    {d, ""} = Integer.parse(hex, 16)
    d
  end
end
