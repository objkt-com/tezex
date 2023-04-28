defmodule Tezex.Crypto.Test do
  use ExUnit.Case, async: true
  doctest Tezex.Crypto
  alias Tezex.Crypto

  @msg_sig_pubkey [
    {"tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z",
     "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d31365430383a35343a34362e3638395a206c6f6c",
     "edsigtqqVg7CM2ynDXRHUfVEdL4LxKAJ1xrM1poMPXZdwVQ3SQ6YBkqPcAuaGYbeqUTrg374dDNFvJKCVfMA7T1Vrotg91Hsuam",
     "edpktsPhZ8weLEXqf4Fo5FS9Qx8ZuX4QpEBEwe63L747G8iDjTAF6w"},
    {"tz1LKpeN8ZSSFNyTWiBNaE4u4sjaq7J1Vz2z",
     "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d31365432303a34353a35342e3034365a206c6f6c",
     "edsigtv33HXjUxCSgs8SQ3DMpmJ1eVtAShY3RcSd1L9K1Y5pJnUm3Fg5eF2fHgX1NdaSKc5yGo5T5C6VYpj7nUJvi62TWdf8Fco",
     "edpktsPhZ8weLEXqf4Fo5FS9Qx8ZuX4QpEBEwe63L747G8iDjTAF6w"},
    {"tz1L4TadX36D5bqmmBQKg1g4CmvjHtk67toL",
     "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d31365432303a34393a34382e3232335a206c6f6c",
     "edsigtieZWEzUjmuUeLveR2sz7vN1MmAPQt6XNREuTLGtvLg92w8k2Uo5kdZ217KF6mojP3BfoB2adXTuXEv9a8j543tSRNT9zQ",
     "edpkty7h5cdUE7FYbXzmxh89DdD3zyJEiZFhJnZRxFLYygXNb3iro4"},
    {"tz1L4TadX36D5bqmmBQKg1g4CmvjHtk67toL",
     "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d31365432303a35303a33392e3339365a206c6f6c",
     "edsigtbrU2NdAJDjdLNZV7sFSFpTpHGzCbmeirDzkJRVatnkwDDyr79Q9LVEb3v4FJrnm2ofsdhXCox3SoknNtKtU1f6PwX3EvG",
     "edpkty7h5cdUE7FYbXzmxh89DdD3zyJEiZFhJnZRxFLYygXNb3iro4"},
    {"tz1QGCWjNpYmcS6T9qFGYSam25e36WeFUCK4",
     "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d30382d32335431353a32363a33312e3036315a206c6f6c",
     "edsigtivh3xjQpj1XfR2WUMS9vyTtzJxKiGphFcDDUs5Wej1EwAvPNWnnQaPb1hq2QxiChkEh4SjnZopqAv3paCCwfzupochfpB",
     "edpkuxkZD8KAaLWCmeLhYdxn2fGNT5L7nAyXNVhe4ZptRGvegBkdpS"},
    {"tz2BC83pvEAag6r2ZV7kPghNAbjFoiqhCvZx",
     "05010000007154657a6f73205369676e6564204d6573736167653a207369676e206d6520696e20617320747a32424338337076454161673672325a56376b5067684e41626a466f69716843765a78206f6e206f626a6b742e636f6d20617420323032312d31302d30345431383a35393a31332e3939305a",
     "spsig1ZNQaUKNERZSiEiNviqa5EAPkcNASXhfkXtxRatZTDZAnUB4Ra2Jus8b1oEpFnPx8Z6g28pd8vK3R8nPK29JDU5FiSLH5T",
     "sppk7aBerAEA6tv4wzg6FnK7i5YrGtEGFVvNjWhc2QX8bhzpouBVFSW"},
    {"tz3bPFa6mGv8m4Ppn7w5KSDyAbEPwbJNpC9p",
     "0554657a6f73205369676e6564204d6573736167653a2074657a6f732d746573742d642e61707020323032312d31302d30345431333a30303a34332e3830305a206c6f6c",
     "p2sigNdsHrSzfc7oQMFjrbXFiZe3SM4329j1VY6GYY7kRG6Q4L4Ljw1gT4wKRrRqDECxQwTfs967gpe4EDQJo6cSgB79TmFCfg",
     "p2pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa"},
    {"tz3bPFa6mGv8m4Ppn7w5KSDyAbEPwbJNpC9p",
     "05010000008654657a6f73205369676e6564204d6573736167653a20436f6e6669726d696e67206d79206964656e7469747920617320747a3362504661366d4776386d3450706e3777354b5344794162455077624a4e70433970206f6e206f626a6b742e636f6d2c207369673a484d675a79764d51697579684b4171304f7835374963795841344f6a456348",
     "p2sigkXYeimNtVJDr8X3me62Rig7cPogEQ3NPYHcGgnGuuFFy2BqttXHnst3mYyJ68k3jdAE92TKbyGC9hcmmVy1YbxyTJXAc1",
     "p2pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa"}
  ]

  test "verifies valid signatures" do
    for {{address, msg, sig, pubkey}, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
      try do
        assert Crypto.check_signature(address, sig, msg, pubkey)
      rescue
        err ->
          IO.inspect("sig check failed", label: idx)
          raise err
      end
    end
  end

  test "does not verify invalid signatures" do
    # modify one character in the valid signed message to make it invalid
    for {{address, msg, sig, pubkey}, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
      try do
        # replace the 21st character with '9'
        msg = String.replace(msg, ~r/^(.{0,20})(.{1})(.*)/, "\\g{1}9\\g{3}")
        refute Crypto.check_signature(address, sig, msg, pubkey)
      rescue
        err ->
          IO.inspect("sig check should have failed", label: idx)
          raise err
      end
    end

    # modify one character in the valid signature to make it invalid
    for {{address, msg, sig, pubkey}, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
      try do
        # replace the 21st character with '9'
        sig = String.replace(sig, ~r/^(.{0,20})(.{1})(.*)/, "\\g{1}9\\g{3}")
        refute Crypto.check_signature(address, sig, msg, pubkey)
      rescue
        err ->
          IO.inspect("sig check should have failed", label: idx)
          raise err
      end
    end

    # modify one character in the valid pubkey to make it invalid
    for {{address, msg, sig, pubkey}, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
      try do
        # replace the 21st character with '9'
        pubkey = String.replace(pubkey, ~r/^(.{0,20})(.{1})(.*)/, "\\g{1}9\\g{3}")
        refute Crypto.check_signature(address, sig, msg, pubkey)
      rescue
        err ->
          IO.inspect("sig check should have failed", label: idx)
          raise err
      end
    end

    # modify one character in the address to make it invalid
    for {{address, msg, sig, pubkey}, idx} <- Enum.with_index(@msg_sig_pubkey, 1) do
      try do
        # replace the 21st character with '9'
        address = String.replace(address, ~r/^(.{0,20})(.{1})(.*)/, "\\g{1}9\\g{3}")
        refute Crypto.check_signature(address, sig, msg, pubkey)
      rescue
        err ->
          IO.inspect("sig check should have failed", label: idx)
          raise err
      end
    end
  end

  describe "address check" do
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
      assert {:error, :unknown_pubkey_format} ==
               Crypto.derive_address("a3pk65yRxCX65k6qRPrbqGWvfW5JnLB1p3dn1oM5o9cyqLKPPhJaBMa")
    end
  end
end
