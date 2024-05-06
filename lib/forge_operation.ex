defmodule Tezex.ForgeOperation do
  @moduledoc """
  Prepare an operation or an operation group for injection into the Tezos blockchain.

  Mostly ported from pytezos@9352c4579e436b92f8070343964af20747255197
  > pytezos / MIT License / (c) 2020 Baking Bad / (c) 2018 Arthur Breitman
  """

  alias Tezex.Forge

  @operation_tags %{
    "endorsement" => 0,
    "endorsement_with_slot" => 10,
    "proposals" => 5,
    "ballot" => 6,
    "seed_nonce_revelation" => 1,
    "double_endorsement_evidence" => 2,
    "double_baking_evidence" => 3,
    "activate_account" => 4,
    "failing_noop" => 17,
    "reveal" => 107,
    "transaction" => 108,
    "origination" => 109,
    "delegation" => 110,
    "register_global_constant" => 111,
    "transfer_ticket" => 158,
    "smart_rollup_add_messages" => 201,
    "smart_rollup_execute_outbox_message" => 206
  }

  @reserved_entrypoints %{
    "default" => <<0>>,
    "root" => <<1>>,
    "do" => <<2>>,
    "set_delegate" => <<3>>,
    "remove_delegate" => <<4>>,
    "deposit" => <<5>>
  }

  # Checks if the content dictionary has parameters that are not the default 'Unit' type for 'default' entrypoint
  defp has_parameters(content) do
    case content do
      %{"parameters" => %{"entrypoint" => "default", "value" => %{"prim" => "Unit"}}} -> false
      %{"parameters" => _} -> true
      _ -> false
    end
  end

  def entrypoint(entrypoint) do
    case Map.get(@reserved_entrypoints, entrypoint) do
      nil -> <<255>> <> Forge.forge_array(entrypoint, :bytes, 1)
      code -> code
    end
  end

  defp forge_tag(tag) do
    <<tag::size(8)>>
  end

  @spec operation(map()) :: nonempty_binary()
  def operation(content) do
    encoders = %{
      "failing_noop" => &failing_noop/1,
      "activate_account" => &activate_account/1,
      "reveal" => &reveal/1,
      "transaction" => &transaction/1,
      "origination" => &origination/1,
      "delegation" => &delegation/1,
      "endorsement" => &endorsement/1,
      "endorsement_with_slot" => &endorsement_with_slot/1,
      "register_global_constant" => &register_global_constant/1,
      "transfer_ticket" => &transfer_ticket/1,
      "smart_rollup_add_messages" => &smart_rollup_add_messages/1,
      "smart_rollup_execute_outbox_message" => &smart_rollup_execute_outbox_message/1
    }

    encoder = encoders[content["kind"]]

    if is_nil(encoder) do
      raise "No encoder for #{content["kind"]}"
    end

    encoder.(content)
  end

  @spec operation_group(map()) :: nonempty_binary()
  def operation_group(operation_group) do
    [
      Forge.forge_base58(operation_group["branch"]),
      Enum.join(Enum.map(operation_group["contents"], &operation/1))
    ]
    |> IO.iodata_to_binary()
    |> :binary.encode_hex(:lowercase)
  end

  @spec activate_account(map()) :: nonempty_binary()
  def activate_account(content) do
    [
      forge_tag(@operation_tags[content["kind"]]),
      binary_slice(Forge.forge_address(content["pkh"]), 2..-1//1),
      Base.decode16!(content["secret"], case: :mixed)
    ]
    |> IO.iodata_to_binary()
  end

  @spec reveal(map()) :: nonempty_binary()
  def reveal(content) do
    [
      forge_tag(@operation_tags[content["kind"]]),
      Forge.forge_address(content["source"], :bytes, true),
      Forge.forge_nat(String.to_integer(content["fee"])),
      Forge.forge_nat(String.to_integer(content["counter"])),
      Forge.forge_nat(String.to_integer(content["gas_limit"])),
      Forge.forge_nat(String.to_integer(content["storage_limit"])),
      Forge.forge_public_key(content["public_key"])
    ]
    |> IO.iodata_to_binary()
  end

  @spec transaction(map()) :: nonempty_binary()
  def transaction(content) do
    [
      forge_tag(@operation_tags[content["kind"]]),
      Forge.forge_address(content["source"], :bytes, true),
      Forge.forge_nat(String.to_integer(content["fee"])),
      Forge.forge_nat(String.to_integer(content["counter"])),
      Forge.forge_nat(String.to_integer(content["gas_limit"])),
      Forge.forge_nat(String.to_integer(content["storage_limit"])),
      Forge.forge_nat(String.to_integer(content["amount"])),
      Forge.forge_address(content["destination"]),
      if has_parameters(content) do
        params = content["parameters"]

        [
          Forge.forge_bool(true),
          entrypoint(params["entrypoint"]),
          Forge.forge_array(Forge.forge_micheline(params["value"]))
        ]
      else
        Forge.forge_bool(false)
      end
    ]
    |> IO.iodata_to_binary()
  end

  @spec origination(map()) :: nonempty_binary()
  def origination(content) do
    [
      forge_tag(@operation_tags[content["kind"]]),
      Forge.forge_address(content["source"], :bytes, true),
      Forge.forge_nat(String.to_integer(content["fee"])),
      Forge.forge_nat(String.to_integer(content["counter"])),
      Forge.forge_nat(String.to_integer(content["gas_limit"])),
      Forge.forge_nat(String.to_integer(content["storage_limit"])),
      Forge.forge_nat(String.to_integer(content["balance"])),
      case Map.get(content, "delegate") do
        nil ->
          Forge.forge_bool(false)

        delegate ->
          [Forge.forge_bool(true), Forge.forge_address(delegate, :bytes, true)]
      end,
      Forge.forge_script(content["script"])
    ]
    |> IO.iodata_to_binary()
  end

  @spec delegation(map()) :: nonempty_binary()
  def delegation(content) do
    [
      forge_tag(@operation_tags[content["kind"]]),
      Forge.forge_address(content["source"], :bytes, true),
      Forge.forge_nat(String.to_integer(content["fee"])),
      Forge.forge_nat(String.to_integer(content["counter"])),
      Forge.forge_nat(String.to_integer(content["gas_limit"])),
      Forge.forge_nat(String.to_integer(content["storage_limit"])),
      case Map.get(content, "delegate") do
        nil ->
          Forge.forge_bool(false)

        delegate ->
          [Forge.forge_bool(true), Forge.forge_address(delegate, :bytes, true)]
      end
    ]
    |> IO.iodata_to_binary()
  end

  @spec endorsement(map()) :: nonempty_binary()
  def endorsement(content) do
    [forge_tag(content["kind"]), Forge.forge_int32(String.to_integer(content["level"]))]
    |> IO.iodata_to_binary()
  end

  @spec inline_endorsement(map()) :: nonempty_binary()
  def inline_endorsement(content) do
    [
      Forge.forge_base58(content["branch"]),
      Forge.forge_nat(@operation_tags[content["operations"]["kind"]]),
      Forge.forge_int32(String.to_integer(content["operations"]["level"])),
      Forge.forge_base58(content["signature"])
    ]
    |> IO.iodata_to_binary()
  end

  @spec endorsement_with_slot(map()) :: nonempty_binary()
  def endorsement_with_slot(content) do
    [
      forge_tag(content["kind"]),
      Forge.forge_array(inline_endorsement(content["endorsement"])),
      Forge.forge_int16(String.to_integer(content["slot"]))
    ]
    |> IO.iodata_to_binary()
  end

  @spec failing_noop(map()) :: nonempty_binary()
  def failing_noop(content) do
    [forge_tag(content["kind"]), Forge.forge_array(content["arbitrary"])] |> IO.iodata_to_binary()
  end

  @spec register_global_constant(map()) :: nonempty_binary()
  def register_global_constant(content) do
    [
      forge_tag(@operation_tags[content["kind"]]),
      Forge.forge_address(content["source"], :bytes, true),
      Forge.forge_nat(String.to_integer(content["fee"])),
      Forge.forge_nat(String.to_integer(content["counter"])),
      Forge.forge_nat(String.to_integer(content["gas_limit"])),
      Forge.forge_nat(String.to_integer(content["storage_limit"])),
      Forge.forge_array(Forge.forge_micheline(content["value"]))
    ]
    |> IO.iodata_to_binary()
  end

  @spec transfer_ticket(map()) :: nonempty_binary()
  def transfer_ticket(content) do
    [
      forge_tag(@operation_tags[content["kind"]]),
      Forge.forge_address(content["source"], :bytes, true),
      Forge.forge_nat(String.to_integer(content["fee"])),
      Forge.forge_nat(String.to_integer(content["counter"])),
      Forge.forge_nat(String.to_integer(content["gas_limit"])),
      Forge.forge_nat(String.to_integer(content["storage_limit"])),
      Forge.forge_array(Forge.forge_micheline(content["ticket_contents"])),
      Forge.forge_array(Forge.forge_micheline(content["ticket_ty"])),
      Forge.forge_address(content["ticket_ticketer"]),
      Forge.forge_nat(String.to_integer(content["ticket_amount"])),
      Forge.forge_address(content["destination"]),
      Forge.forge_array(content["entrypoint"])
    ]
    |> IO.iodata_to_binary()
  end

  @spec smart_rollup_add_messages(map()) :: nonempty_binary()
  def smart_rollup_add_messages(content) do
    [
      forge_tag(@operation_tags[content["kind"]]),
      Forge.forge_address(content["source"], :bytes, true),
      Forge.forge_nat(String.to_integer(content["fee"])),
      Forge.forge_nat(String.to_integer(content["counter"])),
      Forge.forge_nat(String.to_integer(content["gas_limit"])),
      Forge.forge_nat(String.to_integer(content["storage_limit"])),
      Forge.forge_array(
        Enum.join(
          Enum.map(content["message"], &Forge.forge_array(:binary.decode_hex(&1))),
          ""
        )
      )
    ]
    |> IO.iodata_to_binary()
  end

  @spec smart_rollup_execute_outbox_message(map()) :: nonempty_binary()
  def smart_rollup_execute_outbox_message(content) do
    [
      forge_tag(@operation_tags[content["kind"]]),
      Forge.forge_address(content["source"], :bytes, true),
      Forge.forge_nat(String.to_integer(content["fee"])),
      Forge.forge_nat(String.to_integer(content["counter"])),
      Forge.forge_nat(String.to_integer(content["gas_limit"])),
      Forge.forge_nat(String.to_integer(content["storage_limit"])),
      Forge.forge_base58(content["rollup"]),
      Forge.forge_base58(content["cemented_commitment"]),
      Forge.forge_array(:binary.decode_hex(content["output_proof"]))
    ]
    |> IO.iodata_to_binary()
  end
end
