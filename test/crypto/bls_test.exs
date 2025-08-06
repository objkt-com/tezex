defmodule Tezex.Crypto.BLSTest do
  use ExUnit.Case, async: true

  doctest Tezex.Crypto.BLS, import: true

  alias Tezex.Crypto.BLS
  alias Tezex.Crypto.BLS.Fq
  alias Tezex.Crypto.BLS.G1
  alias Tezex.Crypto.BLS.G2
  alias Tezex.Crypto.BLS.Pairing

  describe "BLS key generation" do
    test "generates valid BLS key from seed" do
      seed = :crypto.strong_rand_bytes(32)
      assert {:ok, bls_key} = BLS.from_seed(seed)
      assert %BLS{} = bls_key
    end

    test "rejects invalid seed sizes" do
      short_seed = :crypto.strong_rand_bytes(31)
      long_seed = :crypto.strong_rand_bytes(33)

      assert {:error, :invalid_seed} = BLS.from_seed(short_seed)
      assert {:error, :invalid_seed} = BLS.from_seed(long_seed)
    end

    test "rejects zero seed" do
      zero_seed = <<0::size(256)>>
      assert {:error, :invalid_seed} = BLS.from_seed(zero_seed)
    end

    test "generates valid BLS key using HKDF key generation" do
      ikm = :crypto.strong_rand_bytes(32)
      assert {:ok, bls_key} = BLS.key_gen(ikm)
      assert %BLS{} = bls_key
    end

    test "key_gen with different key_info produces different keys" do
      ikm = :crypto.strong_rand_bytes(32)
      {:ok, key1} = BLS.key_gen(ikm, "")
      {:ok, key2} = BLS.key_gen(ikm, "test")

      pubkey1 = BLS.get_public_key(key1)
      pubkey2 = BLS.get_public_key(key2)

      refute pubkey1 == pubkey2
    end

    test "rejects insufficient IKM for key_gen" do
      short_ikm = :crypto.strong_rand_bytes(31)
      assert {:error, :invalid_ikm} = BLS.key_gen(short_ikm)
    end

    test "creates BLS key from secret exponent (binary)" do
      secret_bytes = :crypto.strong_rand_bytes(32)
      assert {:ok, bls_key} = BLS.from_secret_exponent(secret_bytes)
      assert %BLS{} = bls_key
    end

    test "creates BLS key from secret exponent (integer)" do
      secret_int = 12345
      assert {:ok, bls_key} = BLS.from_secret_exponent(secret_int)
      assert %BLS{} = bls_key
    end

    test "rejects zero secret exponent" do
      assert {:error, :invalid_secret} = BLS.from_secret_exponent(0)
    end
  end

  describe "BLS public key derivation" do
    test "derives 48-byte public key" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      public_key = BLS.get_public_key(bls_key)
      assert byte_size(public_key) == 48
      assert <<_flag, _rest::binary-size(47)>> = public_key
    end

    test "public keys are deterministic" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key1} = BLS.from_seed(seed)
      {:ok, bls_key2} = BLS.from_seed(seed)

      public_key1 = BLS.get_public_key(bls_key1)
      public_key2 = BLS.get_public_key(bls_key2)

      assert public_key1 == public_key2
    end
  end

  describe "BLS signing and verification" do
    test "signs and verifies messages successfully with default ciphersuite" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      message = "test message"
      public_key = BLS.get_public_key(bls_key)
      signature = BLS.sign(bls_key, message)

      assert byte_size(signature) == 96
      assert BLS.verify(signature, message, public_key)
    end

    test "signs and verifies with message augmentation ciphersuite" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      message = "test message"
      public_key = BLS.get_public_key(bls_key)
      signature = BLS.sign(bls_key, message, :message_augmentation)

      assert byte_size(signature) == 96
      assert BLS.verify(signature, message, public_key, :message_augmentation)
    end

    test "signs and verifies with basic ciphersuite" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      message = "test message"
      public_key = BLS.get_public_key(bls_key)
      signature = BLS.sign(bls_key, message, :basic)

      assert byte_size(signature) == 96
      assert BLS.verify(signature, message, public_key, :basic)
    end

    test "signs and verifies with proof-of-possession ciphersuite" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      message = "test message"
      public_key = BLS.get_public_key(bls_key)
      signature = BLS.sign(bls_key, message, :proof_of_possession)

      assert byte_size(signature) == 96
      assert BLS.verify(signature, message, public_key, :proof_of_possession)
    end

    test "different ciphersuites produce different signatures" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      message = "test message"
      sig_aug = BLS.sign(bls_key, message, :message_augmentation)
      sig_basic = BLS.sign(bls_key, message, :basic)
      sig_pop = BLS.sign(bls_key, message, :proof_of_possession)

      refute sig_aug == sig_basic
      refute sig_aug == sig_pop
      refute sig_basic == sig_pop
    end

    test "signatures are deterministic within ciphersuite" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      message = "test message"
      signature1 = BLS.sign(bls_key, message, :basic)
      signature2 = BLS.sign(bls_key, message, :basic)

      assert signature1 == signature2
    end

    test "verification fails for wrong ciphersuite" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      message = "test message"
      public_key = BLS.get_public_key(bls_key)
      signature = BLS.sign(bls_key, message, :basic)

      refute BLS.verify(signature, message, public_key, :message_augmentation)
    end

    test "verification fails for wrong message" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      message = "test message"
      wrong_message = "wrong message"
      public_key = BLS.get_public_key(bls_key)
      signature = BLS.sign(bls_key, message)

      refute BLS.verify(signature, wrong_message, public_key)
    end

    test "verification fails for wrong public key" do
      seed1 = :crypto.strong_rand_bytes(32)
      seed2 = :crypto.strong_rand_bytes(32)
      {:ok, bls_key1} = BLS.from_seed(seed1)
      {:ok, bls_key2} = BLS.from_seed(seed2)

      message = "test message"
      public_key2 = BLS.get_public_key(bls_key2)
      signature1 = BLS.sign(bls_key1, message)

      refute BLS.verify(signature1, message, public_key2)
    end
  end

  describe "serialization" do
    test "serializes and deserializes secret keys" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      serialized = BLS.serialize_secret_key(bls_key)
      assert byte_size(serialized) == 32

      {:ok, deserialized_key} = BLS.deserialize_secret_key(serialized)

      # Keys should produce the same public key
      original_pubkey = BLS.get_public_key(bls_key)
      deserialized_pubkey = BLS.get_public_key(deserialized_key)
      assert original_pubkey == deserialized_pubkey
    end
  end

  describe "proof-of-possession" do
    test "generates and verifies proof-of-possession" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      public_key = BLS.get_public_key(bls_key)
      proof = BLS.pop_prove(bls_key)

      assert byte_size(proof) == 96
      assert BLS.pop_verify(public_key, proof)
    end

    test "proof-of-possession verification fails for wrong public key" do
      seed1 = :crypto.strong_rand_bytes(32)
      seed2 = :crypto.strong_rand_bytes(32)
      {:ok, bls_key1} = BLS.from_seed(seed1)
      {:ok, bls_key2} = BLS.from_seed(seed2)

      public_key2 = BLS.get_public_key(bls_key2)
      proof1 = BLS.pop_prove(bls_key1)

      refute BLS.pop_verify(public_key2, proof1)
    end

    test "proof-of-possession is deterministic" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)

      proof1 = BLS.pop_prove(bls_key)
      proof2 = BLS.pop_prove(bls_key)

      assert proof1 == proof2
    end
  end

  describe "validation functions" do
    test "validates valid public keys" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)
      public_key = BLS.get_public_key(bls_key)

      assert BLS.validate_public_key(public_key)
    end

    test "validates valid signatures" do
      seed = :crypto.strong_rand_bytes(32)
      {:ok, bls_key} = BLS.from_seed(seed)
      message = "test message"
      signature = BLS.sign(bls_key, message)

      assert BLS.validate_signature(signature)
    end

    test "rejects invalid public key sizes" do
      invalid_pubkey = :crypto.strong_rand_bytes(47)
      refute BLS.validate_public_key(invalid_pubkey)
    end

    test "rejects invalid signature sizes" do
      invalid_signature = :crypto.strong_rand_bytes(95)
      refute BLS.validate_signature(invalid_signature)
    end

    test "rejects uncompressed public keys (c_flag = 0)" do
      # Create a 48-byte public key with c_flag = 0 (bit 7 = 0)
      invalid_pubkey = <<0x00, :crypto.strong_rand_bytes(47)::binary>>
      refute BLS.validate_public_key(invalid_pubkey)
    end

    test "rejects uncompressed signatures (c_flag = 0)" do
      # Create a 96-byte signature with c_flag = 0 (bit 7 = 0)
      invalid_signature = <<0x00, :crypto.strong_rand_bytes(95)::binary>>
      refute BLS.validate_signature(invalid_signature)
    end

    test "rejects infinity public key (pytezos/py_ecc behavior)" do
      # pytezos/py_ecc reject infinity points for public keys (KeyValidate requirement)
      infinity_pubkey = <<0xC0, 0::size(376)>>
      refute BLS.validate_public_key(infinity_pubkey)
    end

    test "validates infinity signature with correct flags" do
      # Infinity point: c_flag=1, b_flag=1, a_flag=0, rest=0
      infinity_signature = <<0xC0, 0::size(760)>>
      # pytezos/py_ecc allow infinity signatures, so this should pass
      # If this fails, it means our G2.from_compressed_bytes doesn't handle infinity properly
      assert BLS.validate_signature(infinity_signature)
    end

    test "rejects infinity public key with wrong a_flag" do
      # Infinity point with a_flag=1 (invalid)
      invalid_infinity = <<0xE0, 0::size(376)>>
      refute BLS.validate_public_key(invalid_infinity)
    end

    test "rejects infinity signature with wrong a_flag" do
      # Infinity point with a_flag=1 (invalid)
      invalid_infinity = <<0xE0, 0::size(760)>>
      refute BLS.validate_signature(invalid_infinity)
    end

    test "rejects infinity public key with non-zero data" do
      # Infinity point with non-zero trailing data
      invalid_infinity = <<0xC0, 1::size(376)>>
      refute BLS.validate_public_key(invalid_infinity)
    end

    test "rejects infinity signature with non-zero data" do
      # Infinity point with non-zero trailing data
      invalid_infinity = <<0xC0, 1::size(760)>>
      refute BLS.validate_signature(invalid_infinity)
    end
  end

  describe "ciphersuite information" do
    test "returns supported ciphersuites" do
      ciphersuites = BLS.ciphersuites()

      assert is_map(ciphersuites)
      assert Map.has_key?(ciphersuites, :basic)
      assert Map.has_key?(ciphersuites, :message_augmentation)
      assert Map.has_key?(ciphersuites, :proof_of_possession)
      assert Map.has_key?(ciphersuites, :pop_tag)

      assert ciphersuites.basic == "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
      assert ciphersuites.message_augmentation == "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_"
      assert ciphersuites.proof_of_possession == "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
      assert ciphersuites.pop_tag == "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    end
  end

  describe "utility functions" do
    test "returns correct sizes" do
      sizes = BLS.sizes()
      assert sizes.secret_key == 32
      assert sizes.public_key == 48
      assert sizes.signature == 96
    end

    test "hex conversion works" do
      binary_data = :crypto.strong_rand_bytes(32)
      hex_string = BLS.to_hex(binary_data)
      {:ok, ^binary_data} = BLS.from_hex(hex_string)
    end
  end

  describe "compatibility tests" do
    test "point parsing from compressed bytes with known coordinates" do
      # Test parsing known values
      pubkey_hex =
        "a0ec3e71a719a25208adc97106b122809210faf45a17db24f10ffb1ac014fac1ab95a4a1967e55b185d4df622685b9e8"

      signature_hex =
        "8ad7a4eabe11532403a1ab37ccbe74c7fe7d6bc27007bfcb95044895f87e475f9e61ddaa4d0279632b65cd1a59373f80039fa2d07a2120c2ad1a2b8383461bcecee9dbdd3c6591e04bcd82993622b6eb2b07dd8342ae946dad92db4a56ffc316"

      pubkey_bytes = Base.decode16!(pubkey_hex, case: :lower)
      signature_bytes = Base.decode16!(signature_hex, case: :lower)

      # Parse and verify public key
      {:ok, parsed_pubkey} = G1.from_compressed_bytes(pubkey_bytes)
      assert G1.is_on_curve?(parsed_pubkey), "Parsed public key should be on G1 curve"

      # Parse and verify signature
      {:ok, parsed_signature} = G2.from_compressed_bytes(signature_bytes)
      assert G2.is_on_curve?(parsed_signature), "Parsed signature should be on G2 curve"

      # Test round-trip serialization
      serialized_pubkey = G1.to_compressed_bytes(parsed_pubkey)
      serialized_signature = G2.to_compressed_bytes(parsed_signature)

      assert serialized_pubkey == pubkey_bytes, "Public key round-trip should be identical"
      assert serialized_signature == signature_bytes, "Signature round-trip should be identical"
    end

    test "low-level pairing verification with known values" do
      # Use exact coordinates for empty message verification
      pubkey_x =
        142_036_200_970_556_624_605_073_339_739_716_744_617_077_682_387_984_972_381_936_269_453_125_935_753_630_950_483_159_198_151_608_064_417_555_529_710_056

      pubkey_y =
        2_483_494_160_399_800_422_427_930_336_203_951_581_951_052_469_458_383_510_716_081_548_592_681_084_410_931_468_919_725_454_864_933_967_710_957_791_304_295

      sig_x_a =
        557_719_713_869_100_899_792_735_884_412_423_612_752_925_881_945_432_348_574_028_740_116_863_323_339_684_350_929_614_457_611_309_439_314_165_214_724_886

      sig_x_b =
        1_668_791_965_312_059_807_836_457_317_548_672_608_113_440_586_303_859_886_296_761_628_901_343_970_400_435_590_790_624_209_989_472_464_715_037_160_193_920

      sig_y_a =
        3_073_558_251_484_980_343_618_784_409_303_188_474_526_020_343_185_103_665_020_440_010_927_948_686_879_511_955_294_538_475_807_051_866_826_701_497_014_912

      sig_y_b =
        778_661_423_249_852_692_826_483_507_760_768_582_493_998_384_356_189_540_302_297_378_665_649_876_608_360_426_793_842_453_334_594_919_142_738_701_066_797

      msg_x_a =
        609_541_815_135_480_221_679_491_242_259_596_245_016_291_916_671_741_893_976_316_083_730_115_841_428_606_231_710_189_903_049_358_019_248_894_441_560_542

      msg_x_b =
        186_747_868_399_426_064_906_369_644_332_149_454_294_179_749_493_253_257_167_219_271_286_836_336_506_747_557_358_696_764_962_145_021_492_044_539_904_337

      msg_y_a =
        2_944_887_354_525_313_774_795_512_408_027_209_769_132_902_684_354_376_758_581_454_117_346_493_697_901_743_995_034_341_243_540_233_875_062_030_159_838_087

      msg_y_b =
        1_196_298_788_400_668_221_187_358_257_261_487_369_865_394_703_637_276_346_955_320_329_475_990_617_992_721_247_881_887_960_289_674_012_968_460_753_206_253

      msg_z_a =
        1_254_755_152_323_327_664_477_040_668_423_524_855_088_184_820_139_927_603_845_787_718_063_604_803_235_971_326_362_296_876_378_755_690_202_205_033_458_489

      msg_z_b =
        3_124_154_259_619_641_509_686_987_122_807_511_096_998_334_884_882_650_306_578_241_574_630_753_320_394_444_748_947_866_047_601_657_825_697_043_248_941_337

      # Build the points
      pubkey_point = %{
        x: Fq.from_integer(pubkey_x),
        y: Fq.from_integer(pubkey_y),
        z: Fq.from_integer(1)
      }

      signature_point = %{
        x: {Fq.from_integer(sig_x_a), Fq.from_integer(sig_x_b)},
        y: {Fq.from_integer(sig_y_a), Fq.from_integer(sig_y_b)},
        z: {Fq.from_integer(1), Fq.from_integer(0)}
      }

      message_point = %{
        x: {Fq.from_integer(msg_x_a), Fq.from_integer(msg_x_b)},
        y: {Fq.from_integer(msg_y_a), Fq.from_integer(msg_y_b)},
        z: {Fq.from_integer(msg_z_a), Fq.from_integer(msg_z_b)}
      }

      # Verify points are valid
      assert G1.is_on_curve?(pubkey_point), "Public key point should be on G1 curve"
      assert G2.is_on_curve?(signature_point), "Signature point should be on G2 curve"
      assert G2.is_on_curve?(message_point), "Message point should be on G2 curve"

      # Compute pairing verification: e(G1, signature) == e(pubkey, H(msg))
      g1_generator = G1.generator()
      e1 = Pairing.pairing(g1_generator, signature_point)
      e2 = Pairing.pairing(pubkey_point, message_point)

      assert Tezex.Crypto.BLS.Fq12.eq?(e1, e2), "Pairings should be equal for valid BLS signature"
    end

    test "empty message verification" do
      seed = <<123::size(256)>>
      message = ""

      expected_pubkey_hex =
        "a0ec3e71a719a25208adc97106b122809210faf45a17db24f10ffb1ac014fac1ab95a4a1967e55b185d4df622685b9e8"

      expected_signature_hex =
        "8ad7a4eabe11532403a1ab37ccbe74c7fe7d6bc27007bfcb95044895f87e475f9e61ddaa4d0279632b65cd1a59373f80039fa2d07a2120c2ad1a2b8383461bcecee9dbdd3c6591e04bcd82993622b6eb2b07dd8342ae946dad92db4a56ffc316"

      expected_pubkey = Base.decode16!(expected_pubkey_hex, case: :lower)
      expected_signature = Base.decode16!(expected_signature_hex, case: :lower)

      # Generate using our implementation
      {:ok, bls_key} = BLS.from_seed(seed)
      actual_pubkey = BLS.get_public_key(bls_key)
      actual_signature = BLS.sign(bls_key, message)

      verification_result = BLS.verify(expected_signature, message, expected_pubkey)
      verification_result_ours = BLS.verify(actual_signature, message, actual_pubkey)

      # Both should be true
      assert expected_pubkey == actual_pubkey
      assert expected_signature == actual_signature
      assert verification_result
      assert verification_result_ours
    end
  end
end
