defmodule Tezex.Forge do
  @moduledoc """
  Convert Tezos Micheline data from/to binary form for injection into the Tezos blockchain (aka forging/unforging Micheline).

  Mostly ported from pytezos@9352c4579e436b92f8070343964af20747255197
  > pytezos / MIT License / (c) 2020 Baking Bad / (c) 2018 Arthur Breitman
  """

  import Bitwise

  alias Tezex.Crypto.Base58Check
  alias Tezex.Zarith

  @typedoc """
  Represents the encoding type for input/output operations.
  Can be either `:bytes` for raw binary data or `:hex` for hexadecimal string representation.
  """
  @type io_encoding :: :bytes | :hex

  @typedoc """
  Represents a base58 encoding configuration.
  """
  @type base58_encoding :: %{
          e_prefix: String.t(),
          e_len: non_neg_integer(),
          d_prefix: binary(),
          d_len: non_neg_integer()
        }

  @base58_encodings [
    # block hash
    %{e_prefix: "B", e_len: 51, d_prefix: <<1, 52>>, d_len: 32},
    # op hash
    %{e_prefix: "o", e_len: 51, d_prefix: <<5, 116>>, d_len: 32},
    # op list hash
    %{e_prefix: "Lo", e_len: 52, d_prefix: <<133, 233>>, d_len: 32},
    # op list list hash
    %{e_prefix: "LLo", e_len: 53, d_prefix: <<29, 159, 109>>, d_len: 32},
    # protocol hash
    %{e_prefix: "P", e_len: 51, d_prefix: <<2, 170>>, d_len: 32},
    # context hash
    %{e_prefix: "Co", e_len: 52, d_prefix: <<79, 199>>, d_len: 32},
    # ed25519 pkh
    %{e_prefix: "tz1", e_len: 36, d_prefix: <<6, 161, 159>>, d_len: 20},
    # secp256k1 pkh
    %{e_prefix: "tz2", e_len: 36, d_prefix: <<6, 161, 161>>, d_len: 20},
    # p256 pkh
    %{e_prefix: "tz3", e_len: 36, d_prefix: <<6, 161, 164>>, d_len: 20},
    # BLS-MinPk
    %{e_prefix: "tz4", e_len: 36, d_prefix: <<6, 161, 16>>, d_len: 20},
    # originated address
    %{e_prefix: "KT1", e_len: 36, d_prefix: <<2, 90, 121>>, d_len: 20},
    # tx_rollup_l2_address
    %{e_prefix: "txr1", e_len: 37, d_prefix: <<1, 128, 120, 31>>, d_len: 20},
    # originated smart rollup address
    %{e_prefix: "sr1", e_len: 36, d_prefix: <<6, 124, 117>>, d_len: 20},
    # smart rollup commitment hash
    %{e_prefix: "src1", e_len: 54, d_prefix: <<17, 165, 134, 138>>, d_len: 32},
    # smart rollup state hash
    %{e_prefix: "srs1", e_len: 54, d_prefix: <<17, 165, 235, 240>>, d_len: 32},
    # cryptobox pkh
    %{e_prefix: "id", e_len: 30, d_prefix: <<153, 103>>, d_len: 16},
    # script expression
    %{e_prefix: "expr", e_len: 54, d_prefix: <<13, 44, 64, 27>>, d_len: 32},
    # ed25519 seed
    %{e_prefix: "edsk", e_len: 54, d_prefix: <<13, 15, 58, 7>>, d_len: 32},
    # ed25519 pubkey
    %{e_prefix: "edpk", e_len: 54, d_prefix: <<13, 15, 37, 217>>, d_len: 32},
    # secp256k1 privkey
    %{e_prefix: "spsk", e_len: 54, d_prefix: <<17, 162, 224, 201>>, d_len: 32},
    # p256 privkey
    %{e_prefix: "p2sk", e_len: 54, d_prefix: <<16, 81, 238, 189>>, d_len: 32},
    # ed25519 enc seed
    %{e_prefix: "edesk", e_len: 88, d_prefix: <<7, 90, 60, 179, 41>>, d_len: 56},
    # secp256k1 enc privkey
    %{e_prefix: "spesk", e_len: 88, d_prefix: <<9, 237, 241, 174, 150>>, d_len: 56},
    # p256 enc privkey
    %{e_prefix: "p2esk", e_len: 88, d_prefix: <<9, 48, 57, 115, 171>>, d_len: 56},
    # secp256k1 pubkey
    %{e_prefix: "sppk", e_len: 55, d_prefix: <<3, 254, 226, 86>>, d_len: 33},
    # p256 pubkey
    %{e_prefix: "p2pk", e_len: 55, d_prefix: <<3, 178, 139, 127>>, d_len: 33},
    # secp256k1 scalar
    %{e_prefix: "SSp", e_len: 53, d_prefix: <<38, 248, 136>>, d_len: 33},
    # secp256k1 element
    %{e_prefix: "GSp", e_len: 53, d_prefix: <<5, 92, 0>>, d_len: 33},
    # ed25519 privkey
    %{e_prefix: "edsk", e_len: 98, d_prefix: <<43, 246, 78, 7>>, d_len: 64},
    # ed25519 sig
    %{e_prefix: "edsig", e_len: 99, d_prefix: <<9, 245, 205, 134, 18>>, d_len: 64},
    # secp256k1 sig
    %{e_prefix: "spsig", e_len: 99, d_prefix: <<13, 115, 101, 19, 63>>, d_len: 64},
    # p256 sig
    %{e_prefix: "p2sig", e_len: 98, d_prefix: <<54, 240, 44, 52>>, d_len: 64},
    # generic sig
    %{e_prefix: "sig", e_len: 96, d_prefix: <<4, 130, 43>>, d_len: 64},
    # chain id
    %{e_prefix: "Net", e_len: 15, d_prefix: <<87, 82, 0>>, d_len: 4},
    # seed nonce hash
    %{e_prefix: "nce", e_len: 53, d_prefix: <<69, 220, 169>>, d_len: 32},
    # blinded pkh
    %{e_prefix: "btz1", e_len: 37, d_prefix: <<1, 2, 49, 223>>, d_len: 20},
    # block_payload_hash
    %{e_prefix: "vh", e_len: 52, d_prefix: <<1, 106, 242>>, d_len: 32}
  ]
  @base58_e_prefix Enum.map(@base58_encodings, fn m ->
                     {m.e_prefix, Map.drop(m, [:e_prefix])}
                   end)
                   |> Map.new()

  # The position represents the encoding value
  @primitives ~w(
    parameter storage code False Elt Left None Pair Right Some True Unit PACK UNPACK BLAKE2B SHA256 SHA512 ABS ADD AMOUNT
    AND BALANCE CAR CDR CHECK_SIGNATURE COMPARE CONCAT CONS CREATE_ACCOUNT CREATE_CONTRACT IMPLICIT_ACCOUNT DIP DROP DUP
    EDIV EMPTY_MAP EMPTY_SET EQ EXEC FAILWITH GE GET GT HASH_KEY IF IF_CONS IF_LEFT IF_NONE INT LAMBDA LE LEFT LOOP LSL
    LSR LT MAP MEM MUL NEG NEQ NIL NONE NOT NOW OR PAIR PUSH RIGHT SIZE SOME SOURCE SENDER SELF STEPS_TO_QUOTA SUB SWAP
    TRANSFER_TOKENS SET_DELEGATE UNIT UPDATE XOR ITER LOOP_LEFT ADDRESS CONTRACT ISNAT CAST RENAME bool contract int key
    key_hash lambda list map big_map nat option or pair set signature string bytes mutez timestamp unit operation address
    SLICE DIG DUG EMPTY_BIG_MAP APPLY chain_id CHAIN_ID LEVEL SELF_ADDRESS never NEVER UNPAIR VOTING_POWER TOTAL_VOTING_POWER
    KECCAK SHA3 PAIRING_CHECK bls12_381_g1 bls12_381_g2 bls12_381_fr sapling_state sapling_transaction_deprecated
    SAPLING_EMPTY_STATE SAPLING_VERIFY_UPDATE ticket TICKET_DEPRECATED READ_TICKET SPLIT_TICKET JOIN_TICKETS GET_AND_UPDATE
    chest chest_key OPEN_CHEST VIEW view constant SUB_MUTEZ tx_rollup_l2_address MIN_BLOCK_TIME sapling_transaction EMIT
    Lambda_rec LAMBDA_REC TICKET BYTES NAT
  )
  @primitive_tags Map.new(Enum.with_index(@primitives))
  @tags_primitive Map.new(Enum.map(Enum.with_index(@primitives), fn {k, v} -> {v, k} end))

  defp prim_tag(int) when is_integer(int), do: @tags_primitive[int]
  defp prim_tag(str) when is_binary(str), do: @primitive_tags[str]

  defp get_tag(args_len, annots_len) do
    tag = min(args_len * 2 + 3 + if(annots_len > 0, do: 1, else: 0), 9)
    <<tag>>
  end

  defp read_tag(tag) do
    {div(tag - 3, 2), rem(tag - 3, 2) != 0}
  end

  @doc """
  Encodes a signed unbounded integer into byte form.

  ## Parameters

    * `value` - The integer to be encoded.
    * `output_encoding` - The encoding type for the output. Defaults to `:bytes`.

  ## Returns

    A binary string representing the encoded integer.

  ## Examples

      iex> forge_int(123)
      <<123>>

      iex> forge_int(123, :hex)
      "7B"

  """
  @spec forge_int(integer(), io_encoding()) :: nonempty_binary()
  def forge_int(value, output_encoding \\ :bytes) when is_integer(value) do
    bin = Zarith.encode(value)

    if rem(byte_size(bin), 2) == 1 do
      "0" <> bin
    else
      bin
    end
    |> :binary.decode_hex()
    |> encode_output(output_encoding)
  end

  @spec forge_int16(integer(), io_encoding()) :: nonempty_binary()
  @spec forge_int16(integer()) :: nonempty_binary()
  def forge_int16(value, output_encoding \\ :bytes) do
    <<value::size(16)>>
    |> encode_output(output_encoding)
  end

  @spec forge_int32(integer(), io_encoding()) :: nonempty_binary()
  @spec forge_int32(integer()) :: nonempty_binary()
  def forge_int32(value, output_encoding \\ :bytes) do
    <<value::size(32)>>
    |> encode_output(output_encoding)
  end

  @doc """
  Decode a signed unbounded integer from bytes.
  """
  @spec unforge_int(binary(), io_encoding()) :: {integer(), non_neg_integer()}
  @spec unforge_int(binary()) :: {integer(), non_neg_integer()}
  def unforge_int(data, input_encoding \\ :bytes) do
    data = decode_input(data, input_encoding)
    {%{int: bin}, n} = Zarith.consume(:binary.encode_hex(data))
    {String.to_integer(bin), div(n, 2)}
  end

  @doc """
  Encode a non-negative integer using LEB128 encoding.
  """
  @spec forge_nat(non_neg_integer(), io_encoding()) :: nonempty_binary()
  @spec forge_nat(non_neg_integer()) :: nonempty_binary()
  def forge_nat(value, output_encoding \\ :bytes) do
    if value < 0 do
      raise ArgumentError, "Value cannot be negative."
    end

    forge_nat_recursive(value)
    |> encode_output(output_encoding)
  end

  defp forge_nat_recursive(value, acc \\ <<>>) do
    byte = value &&& 0x7F
    value = value >>> 7

    if value != 0 do
      forge_nat_recursive(value, <<acc::binary, byte ||| 0x80>>)
    else
      <<acc::binary, byte>>
    end
  end

  @spec unforge_chain_id(binary(), io_encoding()) :: nonempty_binary()
  @spec unforge_chain_id(binary()) :: nonempty_binary()
  def unforge_chain_id(data, input_encoding \\ :bytes) do
    data = decode_input(data, input_encoding)
    encode_with_prefix(data, "Net")
  end

  @spec unforge_signature(binary(), io_encoding()) :: nonempty_binary()
  @spec unforge_signature(binary()) :: nonempty_binary()
  def unforge_signature(data, input_encoding \\ :bytes) do
    data = decode_input(data, input_encoding)
    encode_with_prefix(data, "sig")
  end

  @spec forge_bool(boolean(), io_encoding()) :: nonempty_binary()
  @spec forge_bool(boolean()) :: nonempty_binary()
  def forge_bool(value, output_encoding \\ :bytes) do
    if(value, do: <<255>>, else: <<0>>)
    |> encode_output(output_encoding)
  end

  @spec forge_base58(binary(), io_encoding()) :: binary()
  @spec forge_base58(binary()) :: binary()
  def forge_base58(value, output_encoding \\ :bytes) do
    prefix_len =
      Enum.find_value(@base58_encodings, fn m ->
        if byte_size(value) == m.e_len and String.starts_with?(value, m.e_prefix) do
          byte_size(m.d_prefix)
        else
          false
        end
      end)

    if is_nil(prefix_len) do
      raise "Invalid encoding, prefix or length mismatch."
    end

    Base58Check.decode58!(value)
    |> binary_slice(prefix_len, 32)
    |> encode_output(output_encoding)
  end

  @spec optimize_timestamp(binary()) :: integer()
  def optimize_timestamp(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, 0} -> DateTime.to_unix(datetime)
      _ -> String.to_integer(value)
    end
  end

  @doc """
  Encode address or key hash into bytes.

  - `value` is a base58 encoded address or key_hash
  - `tz_only` indicates that it's a key_hash (will be encoded in a more compact form)
  """
  @spec forge_address(binary(), io_encoding(), boolean()) :: nonempty_binary()
  @spec forge_address(binary(), io_encoding()) :: nonempty_binary()
  @spec forge_address(binary()) :: nonempty_binary()
  def forge_address(value, output_encoding \\ :bytes, tz_only \\ false)
      when is_boolean(tz_only) and is_atom(output_encoding) do
    prefix_len = if String.starts_with?(value, "txr1"), do: 4, else: 3
    prefix = binary_part(value, 0, prefix_len)

    address =
      Base58Check.decode58!(value)
      |> binary_slice(prefix_len, 20)

    case prefix do
      "tz1" -> <<0, 0, address::binary>>
      "tz2" -> <<0, 1, address::binary>>
      "tz3" -> <<0, 2, address::binary>>
      "tz4" -> <<0, 3, address::binary>>
      "KT1" -> <<1, address::binary, 0>>
      "txr1" -> <<2, address::binary, 0>>
      "sr1" -> <<3, address::binary, 0>>
      _ -> raise "Can't forge address: unknown prefix `#{prefix}`"
    end
    |> then(fn res ->
      if tz_only do
        binary_slice(res, 1..-1//1)
      else
        res
      end
    end)
    |> encode_output(output_encoding)
  end

  @spec unforge_address(binary(), io_encoding()) :: nonempty_binary()
  @spec unforge_address(binary()) :: nonempty_binary()
  def unforge_address(data, input_encoding \\ :bytes) do
    data = decode_input(data, input_encoding)

    tz_prefixes = %{
      <<0, 0>> => "tz1",
      <<0, 1>> => "tz2",
      <<0, 2>> => "tz3",
      <<0, 3>> => "tz4"
    }

    tz_prefix =
      Enum.find_value(tz_prefixes, fn {bin_prefix, tz_prefix} ->
        if String.starts_with?(data, bin_prefix) do
          tz_prefix
        end
      end)

    {data, prefix} =
      cond do
        is_binary(tz_prefix) ->
          {binary_slice(data, 2..-1//1), tz_prefix}

        String.starts_with?(data, <<1>>) and String.ends_with?(data, <<0>>) ->
          {binary_slice(data, 1..-2//1), "KT1"}

        String.starts_with?(data, <<2>>) and String.ends_with?(data, <<0>>) ->
          {binary_slice(data, 1..-2//1), "txr1"}

        String.starts_with?(data, <<3>>) and String.ends_with?(data, <<0>>) ->
          {binary_slice(data, 1..-2//1), "sr1"}

        true ->
          {binary_slice(data, 1..-1//1), tz_prefixes[<<0, :binary.at(data, 0)>>]}
      end

    encode_with_prefix(data, prefix)
  end

  @spec forge_contract(binary(), io_encoding()) :: binary()
  @spec forge_contract(binary()) :: binary()
  def forge_contract(value, output_encoding \\ :bytes) do
    [address, entrypoint] = String.split(value, "%", parts: 2)
    address_bytes = forge_address(address)

    if entrypoint != nil && entrypoint != "default" do
      address_bytes <> entrypoint
    else
      address_bytes
    end
    |> encode_output(output_encoding)
  end

  @doc """
  Decode a contract (address + optional entrypoint) from bytes, returning a string with the base58 encoded address and, if present, the entrypoint separated by `%`.
  """
  @spec unforge_contract(binary(), io_encoding()) :: nonempty_binary()
  @spec unforge_contract(binary()) :: nonempty_binary()
  def unforge_contract(data, input_encoding \\ :bytes) do
    data = decode_input(data, input_encoding)
    address = unforge_address(binary_part(data, 0, 22))

    case byte_size(data) > 22 do
      true ->
        entrypoint = binary_part(data, 22, byte_size(data) - 22)
        address <> "%" <> entrypoint

      false ->
        address
    end
  end

  @spec forge_public_key(binary(), io_encoding()) :: nonempty_binary()
  @spec forge_public_key(binary()) :: nonempty_binary()
  def forge_public_key(value, output_encoding \\ :bytes) do
    {:ok, res} = Tezex.Crypto.extract_pubkey(value)
    prefix = binary_part(value, 0, 4)

    case prefix do
      "edpk" -> <<0>> <> res
      "sppk" -> <<1>> <> res
      "p2pk" -> <<2>> <> res
      _ -> raise "Unrecognized key type: #{prefix}"
    end
    |> encode_output(output_encoding)
  end

  @spec unforge_public_key(binary(), io_encoding()) :: nonempty_binary()
  @spec unforge_public_key(binary()) :: nonempty_binary()
  def unforge_public_key(data, input_encoding \\ :bytes) do
    data = decode_input(data, input_encoding)

    key_prefix =
      %{
        <<0>> => <<13, 15, 37, 217>>,
        <<1>> => <<3, 254, 226, 86>>,
        <<2>> => <<3, 178, 139, 127>>
      }

    prefix = key_prefix[binary_part(data, 0, 1)]
    Base58Check.encode(binary_part(data, 1, byte_size(data) - 1), prefix)
  end

  @spec forge_array(binary(), io_encoding(), non_neg_integer()) :: binary()
  @spec forge_array(binary(), io_encoding()) :: binary()
  @spec forge_array(binary()) :: binary()
  def forge_array(data, output_encoding \\ :bytes, len_bytes \\ 4) do
    (<<byte_size(data)::size(len_bytes * 8)>> <> data)
    |> encode_output(output_encoding)
  end

  @spec unforge_array(binary(), io_encoding(), non_neg_integer()) :: {binary(), non_neg_integer()}
  @spec unforge_array(binary(), io_encoding()) :: {binary(), non_neg_integer()}
  @spec unforge_array(binary()) :: {binary(), non_neg_integer()}
  def unforge_array(data, input_encoding \\ :bytes, len_bytes \\ 4) do
    data = decode_input(data, input_encoding)

    if byte_size(data) < len_bytes do
      throw("not enough bytes to parse array length, wanted #{len_bytes}")
    end

    length = :binary.decode_unsigned(binary_slice(data, 0, len_bytes), :big)

    if byte_size(data) < len_bytes + length do
      throw("not enough bytes to parse array body, wanted #{length}")
    end

    array_body = binary_part(data, len_bytes, length)
    {array_body, len_bytes + length}
  end

  @doc """
  Encode a Micheline expression into byte form.
  """
  @spec forge_micheline(list() | map(), io_encoding()) :: binary()
  @spec forge_micheline(list() | map()) :: binary()
  def forge_micheline(data, output_encoding \\ :bytes)

  def forge_micheline(data, output_encoding) when is_list(data) do
    # Handle encoding of list data
    data =
      Enum.map(data, &forge_micheline/1)
      |> Enum.join("")

    (<<2>> <> forge_array(data))
    |> encode_output(output_encoding)
  end

  def forge_micheline(data, output_encoding) when is_map(data) do
    # Handle encoding of map (dictionary) data
    cond do
      Map.has_key?(data, "prim") ->
        args = Map.get(data, "args", [])
        annots = Map.get(data, "annots", [])

        [
          get_tag(length(args), length(annots)),
          prim_tag(data["prim"]),
          if Enum.empty?(args) do
            []
          else
            encoded_args = Enum.join(Enum.map(args, &forge_micheline/1), "")

            args_content =
              if length(args) < 3 do
                encoded_args
              else
                forge_array(encoded_args)
              end

            args_content
          end,
          cond do
            length(annots) > 0 -> forge_array(Enum.join(annots, " "))
            length(args) >= 3 -> <<0, 0, 0, 0>>
            true -> []
          end
        ]

      not is_nil(data["bytes"]) ->
        [<<10>>, forge_array(:binary.decode_hex(data["bytes"]))]

      not is_nil(data["int"]) ->
        [<<0>>, forge_int(String.to_integer(data["int"]))]

      not is_nil(data["string"]) ->
        [<<1>>, forge_array(data["string"])]

      true ->
        raise "Unsupported data format: #{inspect(data)}"
    end
    |> IO.iodata_to_binary()
    |> encode_output(output_encoding)
  end

  def forge_micheline(_data, _) do
    raise "Unsupported data type"
  end

  @doc """
  Parse Micheline map from bytes.
  """
  @spec unforge_micheline(binary(), io_encoding()) :: list() | map()
  @spec unforge_micheline(binary()) :: list() | map()
  def unforge_micheline(data, input_encoding \\ :bytes) do
    data = decode_input(data, input_encoding)
    {result, _ptr} = do_unforge_micheline(data, 0)
    result
  end

  @spec do_unforge_micheline(binary(), integer()) :: {list() | map(), integer()}
  defp do_unforge_micheline(data, ptr) do
    tag = :binary.at(data, ptr)
    ptr = ptr + 1

    case tag do
      0 ->
        {val, offset} = unforge_int(binary_slice(data, ptr..-1//1))
        ptr = ptr + offset
        {%{"int" => "#{val}"}, ptr}

      1 ->
        {val, offset} = unforge_array(binary_slice(data, ptr..-1//1))
        ptr = ptr + offset
        {%{"string" => val}, ptr}

      2 ->
        unforge_sequence(data, ptr)

      tag when tag in 3..9 ->
        {args_len, annots} = read_tag(tag)
        unforge_prim_expr(data, ptr, args_len, annots)

      10 ->
        {val, offset} = unforge_array(binary_slice(data, ptr..-1//1))
        ptr = ptr + offset
        {%{"bytes" => Base.encode16(val, case: :lower)}, ptr}

      _ ->
        raise "Unknown tag: #{tag} at position #{ptr}"
    end
  end

  @typep unforged_res :: list(unforged_res()) | map()
  @spec unforge_sequence(binary(), integer()) :: {unforged_res(), integer()}
  defp unforge_sequence(data, ptr) do
    {_, offset} = unforge_array(binary_slice(data, ptr..-1//1))

    end_ptr = ptr + offset
    ptr = ptr + 4

    {res, ptr} = decode_seq_elements(data, ptr, end_ptr)

    if ptr != end_ptr do
      raise "Out of sequence boundaries"
    end

    {res, ptr}
  end

  @spec decode_seq_elements(binary(), integer(), integer(), list(unforged_res())) ::
          {unforged_res(), integer()}
  defp decode_seq_elements(data, ptr, end_ptr, acc \\ []) do
    if ptr < end_ptr do
      {element, ptr} = do_unforge_micheline(data, ptr)
      decode_seq_elements(data, ptr, end_ptr, [element | acc])
    else
      {Enum.reverse(acc), ptr}
    end
  end

  defp unforge_prim_expr(data, ptr, args_len, annots) do
    tag = :binary.at(data, ptr)
    ptr = ptr + 1

    expr = %{"prim" => prim_tag(tag)}

    {expr, ptr} =
      cond do
        args_len > 0 and args_len < 3 ->
          {args, ptr} =
            Enum.reduce(1..args_len, {[], ptr}, fn _, {args, ptr} ->
              {arg, ptr} = do_unforge_micheline(data, ptr)
              {[arg | args], ptr}
            end)

          expr = Map.put(expr, "args", Enum.reverse(args))
          {expr, ptr}

        args_len == 3 ->
          {seq, ptr} = unforge_sequence(data, ptr)
          expr = Map.put(expr, "args", seq)
          {expr, ptr}

        args_len == 0 ->
          {expr, ptr}

        true ->
          raise "unexpected args len #{args_len}"
      end

    if annots or args_len == 3 do
      {value, offset} = unforge_array(binary_slice(data, ptr..-1//1))
      ptr = ptr + offset

      if byte_size(value) > 0 do
        annots_list = String.split(value, " ")
        {Map.put(expr, "annots", annots_list), ptr}
      else
        {expr, ptr}
      end
    else
      {expr, ptr}
    end
  end

  @spec forge_script(map(), io_encoding()) :: binary()
  @spec forge_script(map()) :: binary()
  def forge_script(script, output_encoding \\ :bytes) do
    code = forge_micheline(script["code"])
    storage = forge_micheline(script["storage"])

    (forge_array(code) <> forge_array(storage))
    |> encode_output(output_encoding)
  end

  @spec forge_script_expr(binary(), io_encoding()) :: nonempty_binary()
  @spec forge_script_expr(binary()) :: nonempty_binary()
  def forge_script_expr(packed_key, output_encoding \\ :bytes) do
    data = Blake2.hash2b(packed_key, 32)

    Base58Check.encode(data, <<13, 44, 64, 27>>)
    |> encode_output(output_encoding)
  end

  defp encode_with_prefix(data, e_prefix) do
    prefix = @base58_e_prefix[e_prefix]

    if is_nil(prefix) or prefix.d_len != byte_size(data) do
      raise "Invalid encoding, prefix or length mismatch."
    end

    Base58Check.encode(data, prefix.d_prefix)
  end

  @spec decode_input(binary(), io_encoding()) :: binary()
  defp decode_input(data, :bytes), do: data
  defp decode_input(data, :hex), do: :binary.decode_hex(data)

  @spec encode_output(binary(), io_encoding()) :: binary()
  defp encode_output(data, :bytes), do: data
  defp encode_output(data, :hex), do: Base.encode16(data, case: :lower)
end
