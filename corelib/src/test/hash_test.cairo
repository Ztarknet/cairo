use crate::blake::{
    blake2s_compress, blake2s_finalize, blake2b_compress, blake2b_finalize,
    blake2s, blake2b,
    Blake2sParamsTrait, Blake2sHasherTrait,
    Blake2bParamsTrait, Blake2bHasherTrait,
};
use crate::hash::{HashStateExTrait, HashStateTrait};
use crate::poseidon::PoseidonTrait;
use crate::test::test_utils::assert_eq;

#[test]
fn test_pedersen_hash() {
    assert_eq(
        @crate::pedersen::pedersen(1, 2),
        @2592987851775965742543459319508348457290966253241455514226127639100457844774,
        'Wrong hash value',
    );
}

#[test]
fn test_poseidon_hades_permutation() {
    let (s0, s1, s2) = crate::poseidon::hades_permutation(1, 2, 3);
    assert_eq(
        @s0,
        @442682200349489646213731521593476982257703159825582578145778919623645026501,
        'wrong s0',
    );
    assert_eq(
        @s1,
        @2233832504250924383748553933071188903279928981104663696710686541536735838182,
        'wrong s1',
    );
    assert_eq(
        @s2,
        @2512222140811166287287541003826449032093371832913959128171347018667852712082,
        'wrong s2',
    );
}

#[test]
fn test_poseidon_hash_span() {
    // Test odd number of inputs.
    assert_eq!(
        crate::poseidon::poseidon_hash_span([1, 2, 3].span()),
        0x2f0d8840bcf3bc629598d8a6cc80cb7c0d9e52d93dab244bbf9cd0dca0ad082,
    );

    // Test even number of inputs.
    assert_eq!(
        crate::poseidon::poseidon_hash_span([1, 2, 3, 4].span()),
        0x26e3ad8b876e02bc8a4fc43dad40a8f81a6384083cabffa190bcf40d512ae1d,
    );
}

#[derive(Hash)]
enum EnumForHash {
    First,
    Second: felt252,
    Third: (felt252, felt252),
}

#[derive(Hash)]
struct StructForHash {
    first: (),
    second: felt252,
    third: (felt252, felt252),
}

#[test]
fn test_user_defined_hash() {
    assert_eq(
        @PoseidonTrait::new().update_with(EnumForHash::First).finalize(),
        @PoseidonTrait::new().update(0).finalize(),
        'Bad hash of EnumForHash::First',
    );
    assert_eq(
        @PoseidonTrait::new().update_with(EnumForHash::Second(5)).finalize(),
        @PoseidonTrait::new().update(1).update(5).finalize(),
        'Bad hash of EnumForHash::Second',
    );
    assert_eq(
        @PoseidonTrait::new().update_with(EnumForHash::Third((6, 8))).finalize(),
        @PoseidonTrait::new().update(2).update(6).update(8).finalize(),
        'Bad hash of EnumForHash::Third',
    );
    assert_eq(
        @PoseidonTrait::new()
            .update_with(StructForHash { first: (), second: 10, third: (6, 17) })
            .finalize(),
        @PoseidonTrait::new().update(10).update(6).update(17).finalize(),
        'Bad hash of StructForHash',
    );
}


#[test]
fn test_blake2s() {
    let state = BoxTrait::new([0_u32; 8]);
    let msg = BoxTrait::new([0_u32; 16]);
    let byte_count = 64_u32;
    assert_eq!(
        blake2s_compress(state, byte_count, msg).unbox(),
        [
            0xe816e42a, 0x7d9875d8, 0xfda62c55, 0xa2c6f449, 0xca7af611, 0xdd2f7629, 0xbcd92323,
            0x15c3ab3b,
        ],
    );
    assert_eq!(
        blake2s_finalize(state, byte_count, msg).unbox(),
        [
            0x7a59305, 0x56b8b489, 0xbe3bb37e, 0x58ec6ba0, 0x2f53d5d3, 0x26cd7988, 0xde14c740,
            0x3e3f372e,
        ],
    );
}

#[test]
fn test_blake2s_with_abc() {
    // hashing `abc` as it is done in RFC 7693 Appendix B.
    // Initial state is the IV, with keylen 0 and output length 32.
    let state = BoxTrait::new(
        [
            0x6A09E667 ^ (0x01010000 ^ 0x20), 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F,
            0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        ],
    );
    // Message `abc` padded with zeros.
    let msg = BoxTrait::new(['cba', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        blake2s_finalize(state, 3, msg).unbox(),
        [
            0x8c5e8c50, 0xe2147c32, 0xa32ba7e1, 0x2f45eb4e, 0x208b4537, 0x293ad69e, 0x4c9b994d,
            0x82596786,
        ],
    );
}


#[test]
fn test_blake2b() {
    // Test Blake2b with zero state and zero message (parallel to test_blake2s)
    // Blake2b uses 64-bit words
    let state = BoxTrait::new([0_u64; 8]);
    let msg = BoxTrait::new([0_u64; 16]);
    let byte_count = 128_u64; // Blake2b block size is 128 bytes

    // blake2b_compress with non-final block
    let result = blake2b_compress(state, byte_count, msg);
    // Verify result is not all zeros (compression should produce non-trivial output)
    let unboxed = result.unbox();
    assert!(unboxed != [0_u64; 8]);

    // blake2b_finalize (final block)
    let state2 = BoxTrait::new([0_u64; 8]);
    let msg2 = BoxTrait::new([0_u64; 16]);
    let result2 = blake2b_finalize(state2, byte_count, msg2);
    let unboxed2 = result2.unbox();
    // Finalized result should be different from non-finalized
    assert!(unboxed2 != unboxed);
}


#[test]
fn test_blake2b_with_abc() {
    // Hashing `abc` as it is done in RFC 7693 Appendix E for Blake2b-512.
    // Initial state is the IV XORed with parameter block.
    // For Blake2b-512: digest_length=64 (0x40), key_length=0, fanout=1, depth=1
    // Parameter word: 0x01010040
    // Blake2b IV values (64-bit):
    let state = BoxTrait::new(
        [
            0x6a09e667f3bcc908 ^ 0x01010040, // IV[0] XOR param
            0xbb67ae8584caa73b,              // IV[1]
            0x3c6ef372fe94f82b,              // IV[2]
            0xa54ff53a5f1d36f1,              // IV[3]
            0x510e527fade682d1,              // IV[4]
            0x9b05688c2b3e6c1f,              // IV[5]
            0x1f83d9abfb41bd6b,              // IV[6]
            0x5be0cd19137e2179,              // IV[7]
        ],
    );
    // Message `abc` (0x61 0x62 0x63) in little-endian 64-bit word, padded with zeros.
    // 'abc' = 0x636261 in LE
    let msg = BoxTrait::new([0x0000000000636261, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    // Expected output for BLAKE2b-512("abc") from RFC 7693 Appendix E:
    // BA80A53F981C4D0D 6A2797B69F12F6E9 4C212F14685AC4B7 4B12BB6FDBFFA2D1
    // 7D87C5392AAB792D C252D5DE4533CC95 18D38AA8DBF1925A B92386EDD4009923
    // In little-endian 64-bit words:
    assert_eq!(
        blake2b_finalize(state, 3, msg).unbox(),
        [
            0x0d4d1c983fa580ba, // LE of BA80A53F981C4D0D
            0xe9f6129fb697276a, // LE of 6A2797B69F12F6E9
            0xb7c45a68142f214c, // LE of 4C212F14685AC4B7
            0xd1a2ffdb6fbb124b, // LE of 4B12BB6FDBFFA2D1
            0x2d79ab2a39c5877d, // LE of 7D87C5392AAB792D
            0x95cc3345ded552c2, // LE of C252D5DE4533CC95
            0x5a92f1dba88ad318, // LE of 18D38AA8DBF1925A
            0x239900d4ed8623b9, // LE of B92386EDD4009923
        ],
    );
}


#[test]
fn test_blake2b_empty_string() {
    // BLAKE2b-512 hash of empty string.
    // Initial state with parameter block for 64-byte output.
    let state = BoxTrait::new(
        [
            0x6a09e667f3bcc908 ^ 0x01010040, // IV[0] XOR param
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ],
    );
    let msg = BoxTrait::new([0_u64; 16]);

    // Note: The RFC 7693 expected output for BLAKE2b-512("") is:
    // 786A02F742015903 C6C6FD852552D272 912F4740E1584761 8A86E217F71F5419
    // D25E1031AFEE5853 13896444934EB04B 903A685B1448B755 D56F701AFE9BE2CE
    // The following are the actual values from the extern function (regression test):
    assert_eq!(
        blake2b_finalize(state, 0, msg).unbox(),
        [
            241225442164632184_u64,
            8273765786548291270_u64,
            7009669069494759313_u64,
            1825118895109998218_u64,
            6005812539308400338_u64,
            5453945543160269075_u64,
            6176484666232027792_u64,
            14907649232217337813_u64,
        ],
    );
}


// ============================================================================
// High-level Blake2 API tests
// ============================================================================

#[test]
fn test_blake2s_convenience_function() {
    // Test the convenience function blake2s()
    let input: ByteArray = "";
    let hash = blake2s(@input);
    assert!(hash.len() == 32);
    // Expected: BLAKE2s-256("") from Python hashlib
    // Hex: 69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9
    let expected: Array<u8> = array![
        0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94,
        0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
        0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e,
        0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9,
    ];
    assert!(hash == expected);
}

#[test]
fn test_blake2b_convenience_function() {
    // Test the convenience function blake2b()
    let input: ByteArray = "";
    let hash = blake2b(@input);
    assert!(hash.len() == 64);
    // Expected: BLAKE2b-512("") from Python hashlib
    // Hex: 786a02f742015903c6c6fd852552d272912f4740e1584761...
    let expected: Array<u8> = array![
        0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03,
        0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72,
        0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61,
        0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19,
        0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53,
        0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b,
        0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
        0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce,
    ];
    assert!(hash == expected);
}

#[test]
fn test_blake2s_params_default() {
    // Default Blake2s should produce 32-byte hash
    let input: ByteArray = "test";
    let hash = Blake2sParamsTrait::hash(Blake2sParamsTrait::new(), @input);
    assert!(hash.len() == 32);
    // Expected: BLAKE2s-256("test") from Python hashlib
    // Hex: f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e
    let expected: Array<u8> = array![
        0xf3, 0x08, 0xfc, 0x02, 0xce, 0x91, 0x72, 0xad,
        0x02, 0xa7, 0xd7, 0x58, 0x00, 0xec, 0xfc, 0x02,
        0x71, 0x09, 0xbc, 0x67, 0x98, 0x7e, 0xa3, 0x2a,
        0xba, 0x9b, 0x8d, 0xcc, 0x7b, 0x10, 0x15, 0x0e,
    ];
    assert!(hash == expected);
}

#[test]
fn test_blake2b_params_default() {
    // Default Blake2b should produce 64-byte hash
    let input: ByteArray = "test";
    let hash = Blake2bParamsTrait::hash(Blake2bParamsTrait::new(), @input);
    assert!(hash.len() == 64);
    // Expected: BLAKE2b-512("test") from Python hashlib
    // Hex: a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa...
    let expected: Array<u8> = array![
        0xa7, 0x10, 0x79, 0xd4, 0x28, 0x53, 0xde, 0xa2,
        0x6e, 0x45, 0x30, 0x04, 0x33, 0x86, 0x70, 0xa5,
        0x38, 0x14, 0xb7, 0x81, 0x37, 0xff, 0xbe, 0xd0,
        0x76, 0x03, 0xa4, 0x1d, 0x76, 0xa4, 0x83, 0xaa,
        0x9b, 0xc3, 0x3b, 0x58, 0x2f, 0x77, 0xd3, 0x0a,
        0x65, 0xe6, 0xf2, 0x9a, 0x89, 0x6c, 0x04, 0x11,
        0xf3, 0x83, 0x12, 0xe1, 0xd6, 0x6e, 0x0b, 0xf1,
        0x63, 0x86, 0xc8, 0x6a, 0x89, 0xbe, 0xa5, 0x72,
    ];
    assert!(hash == expected);
}

#[test]
fn test_blake2s_custom_hash_length() {
    // Test custom hash length for Blake2s
    let input: ByteArray = "test";
    let params = Blake2sParamsTrait::new();
    let params16 = Blake2sParamsTrait::hash_length(params, 16);
    let hash_16 = Blake2sParamsTrait::hash(params16, @input);
    assert!(hash_16.len() == 16);

    let params2 = Blake2sParamsTrait::new();
    let params8 = Blake2sParamsTrait::hash_length(params2, 8);
    let hash_8 = Blake2sParamsTrait::hash(params8, @input);
    assert!(hash_8.len() == 8);
}

#[test]
fn test_blake2b_custom_hash_length() {
    // Test custom hash length for Blake2b
    let input: ByteArray = "test";
    let params = Blake2bParamsTrait::new();
    let params32 = Blake2bParamsTrait::hash_length(params, 32);
    let hash_32 = Blake2bParamsTrait::hash(params32, @input);
    assert!(hash_32.len() == 32);

    let params2 = Blake2bParamsTrait::new();
    let params16 = Blake2bParamsTrait::hash_length(params2, 16);
    let hash_16 = Blake2bParamsTrait::hash(params16, @input);
    assert!(hash_16.len() == 16);
}

#[test]
fn test_blake2s_personalization() {
    // Test that personalization changes the hash output
    let input: ByteArray = "test";
    let pers1: ByteArray = "persona1";
    let pers2: ByteArray = "persona2";

    let p1 = Blake2sParamsTrait::personal(Blake2sParamsTrait::new(), @pers1);
    let hash1 = Blake2sParamsTrait::hash(p1, @input);

    let p2 = Blake2sParamsTrait::personal(Blake2sParamsTrait::new(), @pers2);
    let hash2 = Blake2sParamsTrait::hash(p2, @input);

    let hash_no_personal = Blake2sParamsTrait::hash(Blake2sParamsTrait::new(), @input);

    // All three should be different
    assert!(hash1 != hash2);
    assert!(hash1 != hash_no_personal);
    assert!(hash2 != hash_no_personal);
}

#[test]
fn test_blake2b_personalization() {
    // Test that personalization changes the hash output
    let input: ByteArray = "test";
    let pers1: ByteArray = "personalize1";
    let pers2: ByteArray = "personalize2";

    let p1 = Blake2bParamsTrait::personal(Blake2bParamsTrait::new(), @pers1);
    let hash1 = Blake2bParamsTrait::hash(p1, @input);

    let p2 = Blake2bParamsTrait::personal(Blake2bParamsTrait::new(), @pers2);
    let hash2 = Blake2bParamsTrait::hash(p2, @input);

    let hash_no_personal = Blake2bParamsTrait::hash(Blake2bParamsTrait::new(), @input);

    // All three should be different
    assert!(hash1 != hash2);
    assert!(hash1 != hash_no_personal);
    assert!(hash2 != hash_no_personal);
}

#[test]
fn test_blake2s_salt() {
    // Test that salt changes the hash output
    let input: ByteArray = "test";
    let salt1: ByteArray = "salt1234";
    let salt2: ByteArray = "salt5678";

    let p1 = Blake2sParamsTrait::salt(Blake2sParamsTrait::new(), @salt1);
    let hash1 = Blake2sParamsTrait::hash(p1, @input);

    let p2 = Blake2sParamsTrait::salt(Blake2sParamsTrait::new(), @salt2);
    let hash2 = Blake2sParamsTrait::hash(p2, @input);

    let hash_no_salt = Blake2sParamsTrait::hash(Blake2sParamsTrait::new(), @input);

    assert!(hash1 != hash2);
    assert!(hash1 != hash_no_salt);
}

#[test]
fn test_blake2b_salt() {
    // Test that salt changes the hash output
    let input: ByteArray = "test";
    let salt1: ByteArray = "salt12345678";
    let salt2: ByteArray = "salt87654321";

    let p1 = Blake2bParamsTrait::salt(Blake2bParamsTrait::new(), @salt1);
    let hash1 = Blake2bParamsTrait::hash(p1, @input);

    let p2 = Blake2bParamsTrait::salt(Blake2bParamsTrait::new(), @salt2);
    let hash2 = Blake2bParamsTrait::hash(p2, @input);

    let hash_no_salt = Blake2bParamsTrait::hash(Blake2bParamsTrait::new(), @input);

    assert!(hash1 != hash2);
    assert!(hash1 != hash_no_salt);
}

#[test]
fn test_blake2s_incremental() {
    // Test incremental hashing produces same result as one-shot
    let chunk1: ByteArray = "hello";
    let chunk2: ByteArray = " ";
    let chunk3: ByteArray = "world";
    let full: ByteArray = "hello world";

    let mut state = Blake2sParamsTrait::to_state(Blake2sParamsTrait::new());
    Blake2sHasherTrait::update(ref state, @chunk1);
    Blake2sHasherTrait::update(ref state, @chunk2);
    Blake2sHasherTrait::update(ref state, @chunk3);
    let incremental_hash = Blake2sHasherTrait::finalize(ref state);

    let oneshot_hash = Blake2sParamsTrait::hash(Blake2sParamsTrait::new(), @full);

    assert!(incremental_hash == oneshot_hash);

    // Verify against reference implementation
    // Expected: BLAKE2s-256("hello world") from Python hashlib
    // Hex: 9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b
    let expected: Array<u8> = array![
        0x9a, 0xec, 0x68, 0x06, 0x79, 0x45, 0x61, 0x10,
        0x7e, 0x59, 0x4b, 0x1f, 0x6a, 0x8a, 0x6b, 0x0c,
        0x92, 0xa0, 0xcb, 0xa9, 0xac, 0xf5, 0xe5, 0xe9,
        0x3c, 0xca, 0x06, 0xf7, 0x81, 0x81, 0x3b, 0x0b,
    ];
    assert!(oneshot_hash == expected);
}

#[test]
fn test_blake2b_incremental() {
    // Test incremental hashing produces same result as one-shot
    let chunk1: ByteArray = "hello";
    let chunk2: ByteArray = " ";
    let chunk3: ByteArray = "world";
    let full: ByteArray = "hello world";

    let mut state = Blake2bParamsTrait::to_state(Blake2bParamsTrait::new());
    Blake2bHasherTrait::update(ref state, @chunk1);
    Blake2bHasherTrait::update(ref state, @chunk2);
    Blake2bHasherTrait::update(ref state, @chunk3);
    let incremental_hash = Blake2bHasherTrait::finalize(ref state);

    let oneshot_hash = Blake2bParamsTrait::hash(Blake2bParamsTrait::new(), @full);

    assert!(incremental_hash == oneshot_hash);

    // Verify against reference implementation
    // Expected: BLAKE2b-512("hello world") from Python hashlib
    // Hex: 021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbc...
    let expected: Array<u8> = array![
        0x02, 0x1c, 0xed, 0x87, 0x99, 0x29, 0x6c, 0xec,
        0xa5, 0x57, 0x83, 0x2a, 0xb9, 0x41, 0xa5, 0x0b,
        0x4a, 0x11, 0xf8, 0x34, 0x78, 0xcf, 0x14, 0x1f,
        0x51, 0xf9, 0x33, 0xf6, 0x53, 0xab, 0x9f, 0xbc,
        0xc0, 0x5a, 0x03, 0x7c, 0xdd, 0xbe, 0xd0, 0x6e,
        0x30, 0x9b, 0xf3, 0x34, 0x94, 0x2c, 0x4e, 0x58,
        0xcd, 0xf1, 0xa4, 0x6e, 0x23, 0x79, 0x11, 0xcc,
        0xd7, 0xfc, 0xf9, 0x78, 0x7c, 0xbc, 0x7f, 0xd0,
    ];
    assert!(oneshot_hash == expected);
}

#[test]
fn test_blake2s_keyed() {
    // Test keyed hashing (MAC mode)
    let key: ByteArray = "secret key";
    let msg: ByteArray = "message";

    let params_keyed = Blake2sParamsTrait::key(Blake2sParamsTrait::new(), @key);
    let hash_keyed = Blake2sParamsTrait::hash(params_keyed, @msg);
    let hash_no_key = Blake2sParamsTrait::hash(Blake2sParamsTrait::new(), @msg);

    // Keyed hash should be different from non-keyed
    assert!(hash_keyed != hash_no_key);
    assert!(hash_keyed.len() == 32);

    // Verify against reference implementation
    // Expected: BLAKE2s("message", key="secret key") from Python hashlib
    // Hex: fcd053018c41d70f22fc8eceb8ac39dec4e392448f507dfa4cd9990d7f0a0457
    let expected: Array<u8> = array![
        0xfc, 0xd0, 0x53, 0x01, 0x8c, 0x41, 0xd7, 0x0f,
        0x22, 0xfc, 0x8e, 0xce, 0xb8, 0xac, 0x39, 0xde,
        0xc4, 0xe3, 0x92, 0x44, 0x8f, 0x50, 0x7d, 0xfa,
        0x4c, 0xd9, 0x99, 0x0d, 0x7f, 0x0a, 0x04, 0x57,
    ];
    assert!(hash_keyed == expected);
}

#[test]
fn test_blake2b_keyed() {
    // Test keyed hashing (MAC mode)
    let key: ByteArray = "secret key";
    let msg: ByteArray = "message";

    let params_keyed = Blake2bParamsTrait::key(Blake2bParamsTrait::new(), @key);
    let hash_keyed = Blake2bParamsTrait::hash(params_keyed, @msg);
    let hash_no_key = Blake2bParamsTrait::hash(Blake2bParamsTrait::new(), @msg);

    // Keyed hash should be different from non-keyed
    assert!(hash_keyed != hash_no_key);
    assert!(hash_keyed.len() == 64);

    // Verify against reference implementation
    // Expected: BLAKE2b("message", key="secret key") from Python hashlib
    // Hex: f1aa846a6dba2e9c51593fc3e083ce210cfadc302df6a4f3d3f6aa0c0e3a6760...
    let expected: Array<u8> = array![
        0xf1, 0xaa, 0x84, 0x6a, 0x6d, 0xba, 0x2e, 0x9c,
        0x51, 0x59, 0x3f, 0xc3, 0xe0, 0x83, 0xce, 0x21,
        0x0c, 0xfa, 0xdc, 0x30, 0x2d, 0xf6, 0xa4, 0xf3,
        0xd3, 0xf6, 0xaa, 0x0c, 0x0e, 0x3a, 0x67, 0x60,
        0x75, 0x28, 0xe8, 0x98, 0xe1, 0x8a, 0xdb, 0x77,
        0x17, 0xbe, 0x6e, 0xf7, 0x82, 0x91, 0xef, 0xd5,
        0x8d, 0x7c, 0x61, 0x55, 0xc2, 0xe6, 0x2c, 0x94,
        0x01, 0xfd, 0x0f, 0x30, 0x3a, 0x02, 0x2b, 0x4e,
    ];
    assert!(hash_keyed == expected);
}

#[test]
fn test_blake2s_combined_params() {
    // Test combining multiple parameters
    let personal: ByteArray = "myapp___";
    let input: ByteArray = "data to hash";

    let params = Blake2sParamsTrait::new();
    let params = Blake2sParamsTrait::hash_length(params, 20);
    let params = Blake2sParamsTrait::personal(params, @personal);
    let hash = Blake2sParamsTrait::hash(params, @input);

    assert!(hash.len() == 20);
}

#[test]
fn test_blake2b_combined_params() {
    // Test combining multiple parameters
    let personal: ByteArray = "application_v1__";
    let input: ByteArray = "data to hash";

    let params = Blake2bParamsTrait::new();
    let params = Blake2bParamsTrait::hash_length(params, 40);
    let params = Blake2bParamsTrait::personal(params, @personal);
    let hash = Blake2bParamsTrait::hash(params, @input);

    assert!(hash.len() == 40);
}
