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

  @spec operation(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def operation(content) do
    case content["kind"] do
      "failing_noop" -> failing_noop(content)
      "activate_account" -> activate_account(content)
      "reveal" -> reveal(content)
      "transaction" -> transaction(content)
      "origination" -> origination(content)
      "delegation" -> delegation(content)
      "endorsement" -> endorsement(content)
      "endorsement_with_slot" -> endorsement_with_slot(content)
      "register_global_constant" -> register_global_constant(content)
      "transfer_ticket" -> transfer_ticket(content)
      "smart_rollup_add_messages" -> smart_rollup_add_messages(content)
      "smart_rollup_execute_outbox_message" -> smart_rollup_execute_outbox_message(content)
    end
  end

  @spec operation_group(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def operation_group(operation_group) do
    case validate_required_keys(operation_group, ~w(branch contents)) do
      :ok ->
        operations =
          Enum.map(operation_group["contents"], &operation/1)
          |> Enum.map(fn {:ok, operation} -> operation end)

        content =
          [
            Forge.forge_base58(operation_group["branch"]),
            Enum.join(operations)
          ]
          |> IO.iodata_to_binary()
          |> Base.encode16(case: :lower)

        {:ok, content}

      err ->
        err
    end
  end

  @spec activate_account(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def activate_account(content) do
    case validate_required_keys(content, ~w(kind pkh secret)) do
      :ok ->
        content =
          [
            forge_tag(@operation_tags[content["kind"]]),
            binary_slice(Forge.forge_address(content["pkh"]), 2..-1//1),
            Base.decode16!(content["secret"], case: :mixed)
          ]
          |> IO.iodata_to_binary()

        {:ok, content}

      err ->
        err
    end
  end

  @spec reveal(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def reveal(content) do
    case validate_required_keys(
           content,
           ~w(kind source fee counter gas_limit storage_limit public_key)
         ) do
      :ok ->
        content =
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

        {:ok, content}

      err ->
        err
    end
  end

  @spec transaction(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def transaction(content) do
    case validate_required_keys(
           content,
           ~w(kind source fee counter gas_limit storage_limit amount destination)
         ) do
      :ok ->
        content =
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
              :ok =
                validate_required_keys(
                  content,
                  ~w(parameters parameters.entrypoint parameters.value)
                )

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

        {:ok, content}

      err ->
        err
    end
  end

  @spec origination(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def origination(content) do
    case validate_required_keys(
           content,
           ~w(kind source fee counter gas_limit storage_limit balance)
         ) do
      :ok ->
        content =
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

        {:ok, content}

      err ->
        err
    end
  end

  @spec delegation(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def delegation(content) do
    case validate_required_keys(
           content,
           ~w(kind source fee counter gas_limit storage_limit)
         ) do
      :ok ->
        content =
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

        {:ok, content}

      err ->
        err
    end
  end

  @spec endorsement(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def endorsement(content) do
    case validate_required_keys(content, ~w(kind level)) do
      :ok ->
        content =
          [forge_tag(content["kind"]), Forge.forge_int32(String.to_integer(content["level"]))]
          |> IO.iodata_to_binary()

        {:ok, content}

      err ->
        err
    end
  end

  @spec inline_endorsement(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def inline_endorsement(content) do
    case validate_required_keys(
           content,
           ~w(branch operations operations.kind operations.level signature)
         ) do
      :ok ->
        content =
          [
            Forge.forge_base58(content["branch"]),
            Forge.forge_nat(@operation_tags[content["operations"]["kind"]]),
            Forge.forge_int32(String.to_integer(content["operations"]["level"])),
            Forge.forge_base58(content["signature"])
          ]
          |> IO.iodata_to_binary()

        {:ok, content}

      err ->
        err
    end
  end

  @spec endorsement_with_slot(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def endorsement_with_slot(content) do
    case validate_required_keys(content, ~w(kind endorsement slot)) do
      :ok ->
        {:ok, endorsement} = inline_endorsement(content["endorsement"])

        content =
          [
            forge_tag(content["kind"]),
            Forge.forge_array(endorsement),
            Forge.forge_int16(String.to_integer(content["slot"]))
          ]
          |> IO.iodata_to_binary()

        {:ok, content}

      err ->
        err
    end
  end

  @spec failing_noop(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def failing_noop(content) do
    case validate_required_keys(content, ~w(kind arbitrary)) do
      :ok ->
        content =
          [forge_tag(content["kind"]), Forge.forge_array(content["arbitrary"])]
          |> IO.iodata_to_binary()

        {:ok, content}

      err ->
        err
    end
  end

  @spec register_global_constant(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def register_global_constant(content) do
    case validate_required_keys(
           content,
           ~w(kind source fee counter gas_limit storage_limit value)
         ) do
      :ok ->
        content =
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

        {:ok, content}

      err ->
        err
    end
  end

  @spec transfer_ticket(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def transfer_ticket(content) do
    case validate_required_keys(
           content,
           ~w(kind source fee counter gas_limit storage_limit ticket_contents ticket_ty ticket_ticketer ticket_amount destination entrypoint)
         ) do
      :ok ->
        content =
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

        {:ok, content}

      err ->
        err
    end
  end

  @spec smart_rollup_add_messages(map()) :: {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def smart_rollup_add_messages(content) do
    case validate_required_keys(
           content,
           ~w(kind source fee counter gas_limit storage_limit message)
         ) do
      :ok ->
        content =
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

        {:ok, content}

      err ->
        err
    end
  end

  @spec smart_rollup_execute_outbox_message(map()) ::
          {:ok, nonempty_binary()} | {:error, nonempty_binary()}
  def smart_rollup_execute_outbox_message(content) do
    case validate_required_keys(
           content,
           ~w(kind source fee counter gas_limit storage_limit rollup cemented_commitment output_proof)
         ) do
      :ok ->
        content =
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

        {:ok, content}

      err ->
        err
    end
  end

  @spec validate_required_keys(map(), list()) :: :ok | {:error, nonempty_binary()}
  def validate_required_keys(map, required_keys, acc \\ "")
      when is_map(map) and is_list(required_keys) do
    required_keys = Enum.group_by(required_keys, &String.contains?(&1, "."))

    root = Map.get(required_keys, false, [])
    missing_keys = root -- Map.keys(map)

    if Enum.empty?(missing_keys) do
      next = Map.get(required_keys, true, [])

      if Enum.empty?(next) do
        :ok
      else
        Enum.group_by(
          next,
          fn v ->
            [a, _] = String.split(v, ".", parts: 2)
            a
          end,
          fn v ->
            [_, b] = String.split(v, ".", parts: 2)
            b
          end
        )
        |> Enum.reduce_while(:ok, fn {key, keys}, _ ->
          case validate_required_keys(map[key], keys, "#{acc}#{key}.") do
            :ok -> {:cont, :ok}
            err -> {:halt, err}
          end
        end)
      end
    else
      {:error,
       "Operation content is missing required keys: #{acc}#{Enum.join(missing_keys, ", ")}"}
    end
  end
end
