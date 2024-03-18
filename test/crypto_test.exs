defmodule Tezex.CryptoTest do
  use ExUnit.Case, async: true
  doctest Tezex.Crypto

  alias Tezex.Crypto
  alias Tezex.Micheline

  describe "check_signature/4" do
    @msg_sig_pubkey [
      %{
        "address" => "tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z",
        "message" =>
          "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d31365430383a35343a34362e3638395a206c6f6c",
        "pubkey" => "edpktsPhZ8weLEXqf4Fo5FS9Qx8ZuX4QpEBEwe63L747G8iDjTAF6w",
        "signature" =>
          "edsigtqqVg7CM2ynDXRHUfVEdL4LxKAJ1xrM1poMPXZdwVQ3SQ6YBkqPcAuaGYbeqUTrg374dDNFvJKCVfMA7T1Vrotg91Hsuam"
      },
      %{
        "address" => "tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z",
        "message" =>
          "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d31365432303a34353a35342e3034365a206c6f6c",
        "pubkey" => "edpktsPhZ8weLEXqf4Fo5FS9Qx8ZuX4QpEBEwe63L747G8iDjTAF6w",
        "signature" =>
          "edsigtv33HXjUxCSgs8SQ3DMpmJ1eVtAShY3RcSd1L9K1Y5pJnUm3Fg5eF2fHgX1NdaSKc5yGo5T5C6VYpj7nUJvi62TWdf8Fco"
      },
      %{
        "address" => "tz1L4TadX36D5bqmmBQKg1g4CmvjHtk67toL",
        "message" =>
          "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d31365432303a34393a34382e3232335a206c6f6c",
        "pubkey" => "edpkty7h5cdUE7FYbXzmxh89DdD3zyJEiZFhJnZRxFLYygXNb3iro4",
        "signature" =>
          "edsigtieZWEzUjmuUeLveR2sz7vN1MmAPQt6XNREuTLGtvLg92w8k2Uo5kdZ217KF6mojP3BfoB2adXTuXEv9a8j543tSRNT9zQ"
      },
      %{
        "address" => "tz1L4TadX36D5bqmmBQKg1g4CmvjHtk67toL",
        "message" =>
          "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d31365432303a35303a33392e3339365a206c6f6c",
        "pubkey" => "edpkty7h5cdUE7FYbXzmxh89DdD3zyJEiZFhJnZRxFLYygXNb3iro4",
        "signature" =>
          "edsigtbrU2NdAJDjdLNZV7sFSFpTpHGzCbmeirDzkJRVatnkwDDyr79Q9LVEb3v4FJrnm2ofsdhXCox3SoknNtKtU1f6PwX3EvG"
      },
      %{
        "address" => "tz1QGCWjNpYmcS6T9qFGYSam25e36WeFUCK4",
        "message" =>
          "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d32335431353a32363a33312e3036315a206c6f6c",
        "pubkey" => "edpkuxkZD8KAaLWCmeLhYdxn2fGNT5L7nAyXNVhe4ZptRGvegBkdpS",
        "signature" =>
          "edsigtivh3xjQpj1XfR2WUMS9vyTtzJxKiGphFcDDUs5Wej1EwAvPNWnnQaPb1hq2QxiChkEh4SjnZopqAv3paCCwfzupochfpB"
      },
      %{
        "address" => "tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx",
        "message" =>
          "05010000007154657a6f73205369676e6564204d6573736167653a207369676e206d6520696e20617320747a32424338337076454161673672325a56376b5067684e41626a466f69716843765a78206f6e206f626a6b742e636f6d20617420323032312d31302d30345431383a35393a31332e3939305a",
        "pubkey" => "sppk7aBerAEA6tv4wzg6FnK7i5YrGtEGFVvNjWhc2QX8bhzpouBVFSW",
        "signature" =>
          "spsig1ZNQaUKNERZSiEiNviqa5EAPkcNASXhfkXtxRatZTDZAnUB4Ra2Jus8b1oEpFnPx8Z6g28pd8vK3R8nPK29JDU5FiSLH5T"
      },
      %{
        "address" => "tz2TDtxBkfAy6nyNWnTE7xasWWQppkyKZjDE",
        "message" =>
          "05010000008654657a6f73205369676e6564204d6573736167653a20436f6e6669726d696e67206d79206964656e7469747920617320747a3254447478426b664179366e794e576e54453778617357575170706b794b5a6a4445206f6e206f626a6b742e636f6d2c207369673a4647553039744c3158356b79753665756b487958345a6849376371696c5463",
        "pubkey" => "sppk7cW9woUXS3pwAyhnje5k1yvbRo11PgCBzQMfnFmPg6fKbeLtcoJ",
        "signature" =>
          "spsig1EjqdcNBd2jn2QB8Btn9ZujBBi3pUULPRh8nTx4ACPSQLZKSHh4ihM9BdQ7uPCx5MaZd6gpErzXnUijRSd3E8BqcK5XHrg"
      },
      %{
        "address" => "tz2MVBy9uE95nYoigrX8wE5w58bQWMNyt6jT",
        "message" =>
          "05010000008654657a6f73205369676e6564204d6573736167653a20436f6e6669726d696e67206d79206964656e7469747920617320747a324d56427939754539356e596f69677258387745357735386251574d4e7974366a54206f6e206f626a6b742e636f6d2c207369673a6279644244343078753546746d6b3466336652646558333855784f5f2d3870",
        "pubkey" => "sppk7cR44Ps9c2btiG6PHVYD41aXirE3Nk2mGw1FV4T73RQf2x121dX",
        "signature" =>
          "spsig1W2NuFBUoFgPcATxbcHKkRqqakqwzYcunA84XPPnUK8UJydRFr8tChq87YTYpyknba5Bzj7jenYcKVAYRPgqXpy9QtPYNT"
      },
      %{
        "address" => "tz3bPFa6mGv8m4Ppn7w5KSDyAbEPwbJNpC9p",
        "message" =>
          "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d31302d30345431333a30303a34332e3830305a206c6f6c",
        "pubkey" => "p2pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa",
        "signature" =>
          "p2sigNdsHrSzfc7oQMFjrbXFiZe3SM4329j1VY6GYY7kRG6Q4L4Ljw1gT4wKRrRqDECxQwTfs967gpe4EDQJo6cSgB79TmFCfg"
      },
      %{
        "address" => "tz3bPFa6mGv8m4Ppn7w5KSDyAbEPwbJNpC9p",
        "message" =>
          "05010000008654657a6f73205369676e6564204d6573736167653a20436f6e6669726d696e67206d79206964656e7469747920617320747a3362504661366d4776386d3450706e3777354b5344794162455077624a4e70433970206f6e206f626a6b742e636f6d2c207369673a484d675a79764d51697579684b4171304f7835374963795841344f6a456348",
        "pubkey" => "p2pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa",
        "signature" =>
          "p2sigkXYeimNtVJDr8X3me62Rig7cPogEQ3NPYHcGgnGuuFFy2BqttXHnst3mYyJ68k3jdAE92TKbyGC9hcmmVy1YbxyTJXAc1"
      }
    ]

    test "verifies valid signatures" do
      for {params, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
        try do
          assert :ok =
                   Crypto.check_signature(
                     params["address"],
                     params["signature"],
                     params["message"],
                     params["pubkey"]
                   )
        rescue
          err ->
            IO.inspect("sig check failed", label: idx)
            raise err
        end
      end
    end

    test "verifies valid signature with generic prefix" do
      message =
        "03d0c10e3ed11d7c6e3357f6ef335bab9e8f2bd54d0ce20c482e241191a6e4b8ce6c01be917311d9ac46959750e405d57e268e2ed9e174a80794fbd504e12a4a000141eb3781afed2f69679ff2bbe1c5375950b0e40d00ff000000005e05050505050507070100000024747a32526773486e74516b72794670707352466261313652546656503539684b72654a4d07070100000024747a315a6672455263414c42776d4171776f6e525859565142445439426a4e6a42484a750001"

      pk = "sppk7c7hkPj47yjYFEHX85q46sFJGw6RBrqoVSHwAJAT4e14KJwzoey"
      pkh = "tz2RgsHntQkryFppsRFba16RTfVP59hKreJM"

      sig =
        "sigtofRkQAsLW8ne1HcGhbuBg2Ja2Yt9A2gfpwZFBsdjRWLPSVVqN9BVRpGr7DMwz1e4WjyF8iAjpf1LKyZMcJTSPrDaRzsx"

      assert :ok = Crypto.check_signature(pkh, sig, message, pk)
    end

    test "does not verify invalid signatures" do
      # modify one character in the valid signed message to make it invalid
      for {params, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
        try do
          msg = replace_nth_character(params["message"])

          assert {:error, :bad_signature} =
                   Crypto.check_signature(
                     params["address"],
                     params["signature"],
                     msg,
                     params["pubkey"]
                   )
        rescue
          err ->
            IO.inspect("sig check should have failed", label: idx)
            raise err
        end
      end

      # modify one character in the valid signature to make it invalid
      for {params, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
        try do
          sig = replace_nth_character(params["signature"])

          assert {:error, :bad_signature} =
                   Crypto.check_signature(
                     params["address"],
                     sig,
                     params["message"],
                     params["pubkey"]
                   )
        rescue
          err ->
            IO.inspect("sig check should have failed", label: idx)
            raise err
        end
      end

      # modify one character in the valid pubkey to make it invalid
      for {params, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
        try do
          pubkey = replace_nth_character(params["pubkey"])

          assert {:error, :address_mismatch} =
                   Crypto.check_signature(
                     params["address"],
                     params["signature"],
                     params["message"],
                     pubkey
                   )
        rescue
          err ->
            IO.inspect("sig check should have failed", label: idx)
            raise err
        end
      end

      # modify one character in the address to make it invalid
      for {params, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
        try do
          address = replace_nth_character(params["address"])

          assert {:error, :address_mismatch} =
                   Crypto.check_signature(
                     address,
                     params["signature"],
                     params["message"],
                     params["pubkey"]
                   )
        rescue
          err ->
            IO.inspect("sig check should have failed", label: idx)
            raise err
        end
      end
    end
  end

  describe "derive_address/1" do
    test "key derivation" do
      hashes = [
        {"tz3bPFa6mGv8m4Ppn7w5KSDyAbEPwbJNpC9p",
         "p2pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa"},
        {"tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx",
         "sppk7aBerAEA6tv4wzg6FnK7i5YrGtEGFVvNjWhc2QX8bhzpouBVFSW"},
        {"tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z",
         "edpktsPhZ8weLEXqf4Fo5FS9Qx8ZuX4QpEBEwe63L747G8iDjTAF6w"}
      ]

      for {{pubkeyhash, pubkey}, idx} <- Enum.with_index(hashes, 1) do
        try do
          assert Crypto.derive_address(pubkey) == {:ok, pubkeyhash}
        rescue
          err ->
            IO.inspect("deriv failed", label: idx)
            raise err
        end
      end
    end

    test "key derivation -- invalid pubkey" do
      assert {:error, :invalid_pubkey_format} ==
               Crypto.derive_address("a3pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa")
    end
  end

  describe "sign/3" do
    test "Tz1 64 bytes" do
      encoded_private_key =
        "edskS3DtVSbWbPD1yviMGebjYwWJtruMjDcfAZsH9uba22EzKeYhmQkkraFosFETmEMfFNVcDYQ5QbFerj9ozDKroXZ6mb5oxV"

      pubkey = "edpkvJELH15q7a8ShGRsoULGxLQfUQaGahwRTFywCsnWPPdwnmASRH"
      pubkeyhash = "tz1RvhdZ5pcjD19vCCK9PgZpnmErTba3dsBs"

      bytes = "1234"
      watermark = <<3>>

      signature =
        "sigeeho3jK4MZKsyqcTc9mjhtz9w6enG3AFniufgUXCuXFW7VjShxLoNmxqkQSRYUwP1LHRMere5LrvxcqLgU9KmDGN356Yz"

      assert Crypto.derive_address(pubkey) == {:ok, pubkeyhash}
      assert signature == Crypto.sign(encoded_private_key, bytes, watermark)

      assert true == sign_and_verify(encoded_private_key, pubkey)
    end

    test "Tz1 32 bytes" do
      encoded_private_key = "edsk4TjJWEszkHKono7XMnepVqwi37FrpbVt1KCsifJeAGimxheShG"
      pubkey = "edpkuhmrbunxumoiVdQuxBZUPMmwkPt7yLtY5Qnua3VJVTLWr3vXXa"
      pubkeyhash = "tz1b9kV41KV9N3sp69ycLdSoZ2Ak8jXwtNPv"

      secret_key =
        "edskS8rh49SrQHQxMu5sVsyRXX3Kaodfgbk8qqtTFjxSg2tJbLEtbMnimfJzSz7TTZQeP7EMhZoegHbQWa548RcXJP9kn2J8P8"

      bytes = "1234"
      watermark = <<3>>

      signature =
        "sigpKAnfQGzG4Rk5pV7z9mx2TL9veQCHD7qN4PhsUZMj1BqsumBoApBS9Ue616vKVymxrzfZE2L4h27zzxRUVy6BNPRMpufb"

      assert Crypto.derive_address(pubkey) == {:ok, pubkeyhash}
      assert signature == Crypto.sign(encoded_private_key, bytes, watermark)
      assert signature == Crypto.sign(secret_key, bytes, watermark)

      assert true == sign_and_verify(encoded_private_key, pubkey)
      assert true == sign_and_verify(secret_key, pubkey)
    end

    test "Tz2" do
      encoded_private_key = "spsk2rBDDeUqakQ42nBHDGQTtP3GErb6AahHPwF9bhca3Q5KA5HESE"
      pubkey = "sppk7aqSksZan1AGXuKtCz9UBLZZ77e3ZWGpFxR7ig1Z17GneEhSSbH"
      pubkeyhash = "tz2Ch1abG7FNiibmV26Uzgdsnfni9XGrk5wD"

      bytes = "1234"
      watermark = <<3>>

      signature =
        "sigREwM1SuRN5WzjH5xGJuyeZQ9kWi8XtbA4wRqGTumJwNY18PmF1XQMLCXEQBr4frnriKHWdPUynF1vGUvPcoWrNjb3s5xp"

      assert Crypto.derive_address(pubkey) == {:ok, pubkeyhash}
      assert signature == Crypto.sign(encoded_private_key, bytes, watermark)

      assert true == sign_and_verify(encoded_private_key, pubkey)
    end

    test "Tz2 having 'y' coordinate shorter than 32 bytes" do
      encoded_private_key = "spsk24EJohZHJkZnWEzj3w9wE7BFARpFmq5WAo9oTtqjdJ2t4pyoB3"
      pubkey = "sppk7bcmsCiZmrzrfGpPHnZMx73s6pUC4Tf1zdASQ3rgXfq8uGP3wgV"
      pubkeyhash = "tz2T7hMiWgLAtpsB1JXEP59h3QA8rNVAP1Ue"

      bytes = "1234"
      watermark = <<3>>

      signature =
        "sigmVKa3AcvzDTPGD7rJXkrMh8XMVkVQUkLwGLL3h1APWgicRKBmgjZ3624vqHA2FufBrLTQuPS9YBN1h2Z16kexp9F8NRXp"

      assert Crypto.derive_address(pubkey) == {:ok, pubkeyhash}
      assert signature == Crypto.sign(encoded_private_key, bytes, watermark)

      assert true == sign_and_verify(encoded_private_key, pubkey)
    end

    test "Tz3" do
      encoded_private_key = "p2sk2obfVMEuPUnadAConLWk7Tf4Dt3n4svSgJwrgpamRqJXvaYcg1"
      pubkey = "p2pk66tTYL5EvahKAXncbtbRPBkAnxo3CszzUho5wPCgWauBMyvybuB"
      pubkeyhash = "tz3Lfm6CyfSTZ7EgMckptZZGiPxzs9GK59At"

      bytes = "1234"
      watermark = <<3>>

      signature =
        "sigRUobRZ4oG7CvdtQfNoDe3Gqn8zrLw6RXjXVa84rX3HMzWuCuncWgDqY8wRkssofLUsfbdR6MNGJzDWaNXEwTxDktfrKmj"

      assert Crypto.derive_address(pubkey) == {:ok, pubkeyhash}
      assert signature == Crypto.sign(encoded_private_key, bytes, watermark)

      assert true == sign_and_verify(encoded_private_key, pubkey)
    end

    # test "Tz3 Encrypted" do
    #   encoded_private_key =
    #     "p2esk2TFqgNcoT4u99ut5doGTUFNwo9x4nNvkpM6YMLqXrt4SbFdQnqLM3hoAXLMB2uZYazj6LZGvcoYzk16H6Et"

    #   passphrase = "test1234"
    #   pubkey = "p2pk65zwHGP9MdvANKkp267F4VzoKqL8DMNpPfTHUNKbm8S9DUqqdpw"
    #   pubkeyhash = "tz3hFR7NZtjT2QtzgMQnWb4xMuD6yt2YzXUt"
    #   secret_key = "p2sk2mJNRYqs3UXJzzF44Ym6jk38RVDPVSuLCfNd5ShE5zyVdu8Au9"

    #   bytes = "1234"
    #   watermark = <<3>>

    #   signature =
    #     "sigZiUh7khZmjP1kGSSNe3LQdZC5GMpWHuyFkqcR37pwiGUJrpKaatUxWcRPBE5sHwqfydUsPM4JvK14dBMoHbCxC7VHdMZC"

    #   assert Crypto.derive_address(pubkey) == {:ok, pubkeyhash}
    #   assert signature == Crypto.sign({encoded_private_key, passphrase}, bytes, watermark)
    #   assert signature == Crypto.sign({secret_key, passphrase}, bytes, watermark)
    # end

    # test "Tz3 Encrypted with bytes producing signature that needs padding" do
    #   encoded_private_key = "p2sk2ke47zhFz3znRZj39TW5KKS9VgfU1Hax7KeErgnShNe9oQFQUP"
    #   pubkeyhash = "tz3bBDnPj3Bvek1DeJtsTvicBUPEoTpm2ySt"
    #   secret_key = "p2sk2ke47zhFz3znRZj39TW5KKS9VgfU1Hax7KeErgnShNe9oQFQUP"

    #   bytes =
    #     "03051d7ba791fbe8ccfb6f83dd9c760db5642358909eede2a915a26275e6880b9a6c02a2dea17733a2ef2685e5511bd3f160fd510fea7db50edd8122997800c0843d016910882a9436c31ce1d51570e21ae277bb8d91b800006c02a2dea17733a2ef2685e5511bd3f160fd510fea7df416de812294cd010000016910882a9436c31ce1d51570e21ae277bb8d91b800ff020000004602000000410320053d036d0743035d0100000024747a31655935417161316b5844466f6965624c3238656d7958466f6e65416f5667317a68031e0743036a0032034f034d031b6c02a2dea17733a2ef2685e5511bd3f160fd510fea7dd016df8122a6ca010000016910882a9436c31ce1d51570e21ae277bb8d91b800ff020000003e02000000390320053d036d0743035d0100000024747a3161575850323337424c774e484a6343443462334475744365766871713254315a390346034e031b6c02a2dea17733a2ef2685e5511bd3f160fd510fea7dc916e08122dec9010000016910882a9436c31ce1d51570e21ae277bb8d91b800ff0200000013020000000e0320053d036d053e035d034e031b"

    #   signature =
    #     "p2sigMMsHbzzKh6Eg3cDxfLURiUpTMkyjyPWd7RFtBUH7ZyGBzBqMZH9xZc16akQWZNKkCMHnf1vYjjckPEfru456ikHaFWXFD"

    #   assert signature == Crypto.sign(encoded_private_key, bytes)
    #   assert signature == Crypto.sign(secret_key, bytes)
    # end
  end

  defp sign_and_verify(encoded_private_key, pubkey) do
    msg = "aaøfË"
    msg = Micheline.string_to_micheline_hex(msg)

    signature = Crypto.sign_message(encoded_private_key, msg)
    Crypto.verify_signature(signature, msg, pubkey)
  end

  defp replace_nth_character(input, n \\ 20) do
    re = Regex.compile!("^(.{0,#{n}})(.{1})(.*)")

    replacement =
      if String.at(input, n) == "9" do
        "8"
      else
        "9"
      end

    String.replace(input, re, "\\g{1}#{replacement}\\g{3}")
  end
end
