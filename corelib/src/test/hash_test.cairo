use crate::blake::{blake2s_compress, blake2s_finalize, blake2b_compress, blake2b_finalize};
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

    // Expected output for BLAKE2b-512("") from reference implementation:
    // 786A02F742015903 C6C6FD852552D272 912F4740E1584761 8A86E217F71F5419
    // D25E1031AFEE5853 13896444934EB04B 903A685B1448B755 D56F701AFE9BE2CE
    // In little-endian 64-bit words:
    assert_eq!(
        blake2b_finalize(state, 0, msg).unbox(),
        [
            0x0359014702026a78, // LE of 786A02F742015903
            0x72d2522585fdc6c6, // LE of C6C6FD852552D272
            0x614758e140472f91, // LE of 912F4740E1584761
            0x19541ff717e2868a, // LE of 8A86E217F71F5419
            0x5358eeaf31105ed2, // LE of D25E1031AFEE5853
            0x4bb04e9344648913, // LE of 13896444934EB04B
            0x55b748145b683a90, // LE of 903A685B1448B755
            0xcee29bfe1a706fd5, // LE of D56F701AFE9BE2CE
        ],
    );
}
