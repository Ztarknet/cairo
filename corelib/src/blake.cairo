//! Blake2 cryptographic hash functions.
//!
//! # Examples
//!
//! Simple one-shot hashing:
//! ```
//! use core::blake::blake2s;
//! let hash = blake2s(@"hello world");
//! ```
//!
//! Builder pattern with personalization:
//! ```
//! use core::blake::{Blake2bParams, Blake2bParamsTrait};
//! let hash = Blake2bParams::new()
//!     .hash_length(32)
//!     .personal(@"myapp___")
//!     .hash(@"input data");
//! ```
//!
//! Fluent API with chaining:
//! ```
//! use core::blake::{Blake2sParams, Blake2sParamsTrait, Blake2sHasherTrait};
//! let hash = Blake2sParams::new()
//!     .hash_length(16)
//!     .personal(@"myapp___")
//!     .update(@"input data")
//!     .finalize();
//! ```

use crate::array::ArrayTrait;
use crate::box::BoxTrait;
use crate::byte_array::ByteArrayTrait;
use crate::option::OptionTrait;
use crate::traits::{Into, TryInto};

// ============================================================================
// External Functions (Low-level compression primitives)
// ============================================================================

/// State for Blake2s hash
pub type Blake2sState = Box<[u32; 8]>;

/// The input to the Blake2s compress function.
pub type Blake2sInput = Box<[u32; 16]>;


/// The blake2s compress function, which takes a state, a byte count, and a message, and returns a
/// new state.
/// `byte_count` should be the total number of bytes hashed after hashing the current `msg`.
pub extern fn blake2s_compress(
    state: Blake2sState, byte_count: u32, msg: Blake2sInput,
) -> Blake2sState nopanic;


/// A variant of `blake2s_compress` for the final block of the message.
///
/// The input `msg` must always be exactly 16 `u32` elements, padded with zeros if necessary,
/// regardless of the value of `byte_count`. Using any padding scheme other than zero-padding
/// will produce a different hash output.
pub extern fn blake2s_finalize(
    state: Blake2sState, byte_count: u32, msg: Blake2sInput,
) -> Blake2sState nopanic;


/// State for Blake2b hash
pub type Blake2bState = Box<[u64; 8]>;

/// The input to the Blake2b compress function
pub type Blake2bInput = Box<[u64; 16]>;


/// The blake2b compress function, which takes a state, a byte count, and a message, and returns a
/// new state.
/// `byte_count` should be the total number of bytes hashed after hashing the current `msg`.
/// Blake2b uses a 128-bit counter, but u64 is sufficient for messages up to 2^64 bytes.
pub extern fn blake2b_compress(
    state: Blake2bState, byte_count: u64, msg: Blake2bInput,
) -> Blake2bState nopanic;


/// A variant of `blake2b_compress` for the final block of the message.
///
/// The input `msg` must always be exactly 16 `u64` elements, padded with zeros if necessary,
/// regardless of the value of `byte_count`. Using any padding scheme other than zero-padding
/// will produce a different hash output.
pub extern fn blake2b_finalize(
    state: Blake2bState, byte_count: u64, msg: Blake2bInput,
) -> Blake2bState nopanic;

// ============================================================================
// Constants
// ============================================================================

/// Blake2s constants
pub mod blake2s_const {
    /// Maximum output size in bytes (256 bits)
    pub const OUTBYTES: u8 = 32;
    /// Maximum key size in bytes
    pub const KEYBYTES: u8 = 32;
    /// Salt size in bytes
    pub const SALTBYTES: u8 = 8;
    /// Personalization size in bytes
    pub const PERSONALBYTES: u8 = 8;
    /// Block size in bytes (512 bits)
    pub const BLOCKBYTES: u32 = 64;

    /// Blake2s initialization vectors
    pub const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];
}

/// Blake2b constants
pub mod blake2b_const {
    /// Maximum output size in bytes (512 bits)
    pub const OUTBYTES: u8 = 64;
    /// Maximum key size in bytes
    pub const KEYBYTES: u8 = 64;
    /// Salt size in bytes
    pub const SALTBYTES: u8 = 16;
    /// Personalization size in bytes
    pub const PERSONALBYTES: u8 = 16;
    /// Block size in bytes (1024 bits)
    pub const BLOCKBYTES: u32 = 128;

    /// Blake2b initialization vectors
    pub const IV: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];
}

// ============================================================================
// Blake2s Implementation
// ============================================================================

/// Configuration parameters for Blake2s hashing.
///
/// Use the builder pattern to configure the hash:
/// ```
/// let params = Blake2sParams::new()
///     .hash_length(16)
///     .personal(@"myapp___");
/// ```
#[derive(Drop, Clone)]
pub struct Blake2sParams {
    /// Output digest length (1-32 bytes, default: 32)
    hash_length: u8,
    /// Key length (0-32 bytes, default: 0)
    key_length: u8,
    /// Key bytes (up to 32 bytes)
    key: [u32; 8],
    /// Salt (8 bytes as two u32 words)
    salt: [u32; 2],
    /// Personalization (8 bytes as two u32 words)
    personal: [u32; 2],
    /// Fanout (0 = unlimited, 1 = sequential, default: 1)
    fanout: u8,
    /// Maximum tree depth (1 = sequential, 255 = unlimited, default: 1)
    max_depth: u8,
    /// Leaf maximum byte length (0 = unlimited, default: 0)
    leaf_length: u32,
    /// Node offset (default: 0)
    node_offset: u64,
    /// Node depth (0 = leaf, default: 0)
    node_depth: u8,
    /// Inner hash byte length (default: 0)
    inner_length: u8,
    /// Whether this is the last node in tree mode
    last_node: bool,
}

/// Trait for Blake2sParams builder pattern.
#[generate_trait]
pub impl Blake2sParamsImpl of Blake2sParamsTrait {
    /// Creates a new Blake2sParams with default settings.
    ///
    /// Default configuration:
    /// - hash_length: 32 bytes
    /// - No key
    /// - No salt
    /// - No personalization
    /// - Sequential mode (fanout=1, depth=1)
    fn new() -> Blake2sParams {
        Blake2sParams {
            hash_length: 32,
            key_length: 0,
            key: [0; 8],
            salt: [0; 2],
            personal: [0; 2],
            fanout: 1,
            max_depth: 1,
            leaf_length: 0,
            node_offset: 0,
            node_depth: 0,
            inner_length: 0,
            last_node: false,
        }
    }

    /// Sets the hash output length (1-32 bytes).
    ///
    /// # Panics
    /// Panics if length is 0 or greater than 32.
    fn hash_length(self: Blake2sParams, length: u8) -> Blake2sParams {
        assert(length >= 1 && length <= 32, 'hash_length must be 1-32');
        Blake2sParams { hash_length: length, ..self }
    }

    /// Sets a secret key for keyed hashing (MAC mode).
    ///
    /// The key can be up to 32 bytes. The key is provided as a ByteArray
    /// and will be padded to the block size internally.
    ///
    /// # Panics
    /// Panics if key length exceeds 32 bytes.
    fn key(self: Blake2sParams, key: @ByteArray) -> Blake2sParams {
        let key_len = key.len();
        assert(key_len <= 32, 'key must be <= 32 bytes');

        let key_words = bytes_to_u32_array_8(key);
        Blake2sParams { key_length: key_len.try_into().unwrap(), key: key_words, ..self }
    }

    /// Sets the salt value (up to 8 bytes).
    ///
    /// Salt is used for randomized hashing. If shorter than 8 bytes,
    /// it will be padded with zeros.
    ///
    /// # Panics
    /// Panics if salt exceeds 8 bytes.
    fn salt(self: Blake2sParams, salt: @ByteArray) -> Blake2sParams {
        assert(salt.len() <= 8, 'salt must be <= 8 bytes');
        let salt_words = bytes_to_u32_array_2(salt);
        Blake2sParams { salt: salt_words, ..self }
    }

    /// Sets the personalization string (up to 8 bytes).
    ///
    /// Personalization is used for domain separation. If shorter than
    /// 8 bytes, it will be padded with zeros.
    ///
    /// # Panics
    /// Panics if personalization exceeds 8 bytes.
    fn personal(self: Blake2sParams, personal: @ByteArray) -> Blake2sParams {
        assert(personal.len() <= 8, 'personal must be <= 8 bytes');
        let personal_words = bytes_to_u32_array_2(personal);
        Blake2sParams { personal: personal_words, ..self }
    }

    /// Sets the fanout for tree hashing.
    ///
    /// - 0 = unlimited
    /// - 1 = sequential (default)
    /// - 2-255 = specific fanout
    fn fanout(self: Blake2sParams, fanout: u8) -> Blake2sParams {
        Blake2sParams { fanout, ..self }
    }

    /// Sets the maximum tree depth.
    ///
    /// - 1 = sequential (default)
    /// - 255 = unlimited
    fn max_depth(self: Blake2sParams, depth: u8) -> Blake2sParams {
        assert(depth >= 1, 'max_depth must be >= 1');
        Blake2sParams { max_depth: depth, ..self }
    }

    /// Sets the maximum leaf length for tree hashing.
    fn leaf_length(self: Blake2sParams, length: u32) -> Blake2sParams {
        Blake2sParams { leaf_length: length, ..self }
    }

    /// Sets the node offset for tree hashing.
    fn node_offset(self: Blake2sParams, offset: u64) -> Blake2sParams {
        // For Blake2s, only lower 48 bits are used
        Blake2sParams { node_offset: offset, ..self }
    }

    /// Sets the node depth for tree hashing.
    fn node_depth(self: Blake2sParams, depth: u8) -> Blake2sParams {
        Blake2sParams { node_depth: depth, ..self }
    }

    /// Sets the inner hash length for tree hashing.
    fn inner_length(self: Blake2sParams, length: u8) -> Blake2sParams {
        assert(length <= 32, 'inner_length must be <= 32');
        Blake2sParams { inner_length: length, ..self }
    }

    /// Marks this node as the last in its row for tree hashing.
    fn last_node(self: Blake2sParams, last: bool) -> Blake2sParams {
        Blake2sParams { last_node: last, ..self }
    }

    /// Creates a Hasher for incremental hashing with these parameters.
    fn to_state(self: Blake2sParams) -> Blake2sHasher {
        let h = self.compute_initial_state();
        let mut state = Blake2sHasher {
            h,
            buffer: ArrayTrait::new(),
            pending_word: 0,
            pending_bytes: 0,
            byte_count: 0,
            hash_length: self.hash_length,
            last_node: self.last_node,
            is_keyed: self.key_length > 0,
        };

        // If keyed, the first block is the key padded to block size
        if self.key_length > 0 {
            // Add key as first block (padded to 64 bytes)
            let [k0, k1, k2, k3, k4, k5, k6, k7] = self.key;
            state.buffer.append(k0);
            state.buffer.append(k1);
            state.buffer.append(k2);
            state.buffer.append(k3);
            state.buffer.append(k4);
            state.buffer.append(k5);
            state.buffer.append(k6);
            state.buffer.append(k7);
            // Pad to 16 words (64 bytes)
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
        }

        state
    }

    /// Performs a one-shot hash with these parameters.
    fn hash(self: Blake2sParams, input: @ByteArray) -> Array<u8> {
        let mut state = self.to_state();
        state.update(input);
        state.finalize()
    }

    /// Creates a hasher, updates it with input, and returns it for chaining.
    ///
    /// This enables fluent API usage:
    /// ```
    /// let hash = Blake2sParams::new()
    ///     .hash_length(16)
    ///     .personal(@"myapp___")
    ///     .update(@"input data")
    ///     .finalize();
    /// ```
    fn update(self: Blake2sParams, input: @ByteArray) -> Blake2sHasher {
        let mut state = self.to_state();
        state.update(input);
        state
    }
}

/// Internal methods for Blake2sParams
#[generate_trait]
impl Blake2sParamsInternal of Blake2sParamsInternalTrait {
    /// Computes the initial state by XORing IV with parameter block.
    fn compute_initial_state(self: @Blake2sParams) -> Blake2sState {
        let [iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7] = blake2s_const::IV;

        // Parameter block word 0: hash_length | key_length | fanout | depth
        let p0: u32 = (*self.hash_length).into()
            | ((*self.key_length).into() * 0x100)
            | ((*self.fanout).into() * 0x10000)
            | ((*self.max_depth).into() * 0x1000000);

        // Parameter block word 1: leaf_length
        let p1: u32 = *self.leaf_length;

        // Parameter block words 2-3: node_offset (48 bits) + node_depth + inner_length
        let node_offset_low: u32 = (*self.node_offset & 0xFFFFFFFF).try_into().unwrap();
        let node_offset_high: u32 = ((*self.node_offset / 0x100000000) & 0xFFFF).try_into().unwrap();
        let p2: u32 = node_offset_low;
        let p3: u32 = node_offset_high
            | ((*self.node_depth).into() * 0x10000)
            | ((*self.inner_length).into() * 0x1000000);

        // Parameter block words 4-5: salt
        let [salt0, salt1] = *self.salt;

        // Parameter block words 6-7: personal
        let [pers0, pers1] = *self.personal;

        BoxTrait::new(
            [
                iv0 ^ p0,
                iv1 ^ p1,
                iv2 ^ p2,
                iv3 ^ p3,
                iv4 ^ salt0,
                iv5 ^ salt1,
                iv6 ^ pers0,
                iv7 ^ pers1,
            ],
        )
    }
}

/// Incremental hashing state for Blake2s.
///
/// Use this struct for streaming/incremental hashing. For the low-level
/// compression state type, use `Blake2sState` (which is `Box<[u32; 8]>`).
#[derive(Drop)]
pub struct Blake2sHasher {
    /// Current hash state (8 x 32-bit words)
    h: Blake2sState,
    /// Buffer for complete words (up to 16 x 32-bit words = 64 bytes)
    buffer: Array<u32>,
    /// Current word being built from input bytes
    pending_word: u32,
    /// Number of bytes in the pending word (0-3)
    pending_bytes: u8,
    /// Total bytes processed (not including pending or buffer)
    byte_count: u32,
    /// Configured hash output length
    hash_length: u8,
    /// Whether this is the last node in tree mode
    last_node: bool,
    /// Whether this state was initialized with a key
    is_keyed: bool,
}

/// Trait for Blake2sHasher operations.
#[generate_trait]
pub impl Blake2sHasherImpl of Blake2sHasherTrait {
    /// Creates a new Blake2sHasher with default parameters.
    fn new() -> Blake2sHasher {
        Blake2sParamsImpl::to_state(Blake2sParamsImpl::new())
    }

    /// Updates the hash state with additional input data.
    fn update(ref self: Blake2sHasher, input: @ByteArray) {
        let input_len = input.len();
        if input_len == 0 {
            return;
        }

        // If buffer is full (e.g., from keyed hashing) and we have new data,
        // compress the buffer first
        if self.buffer.len() == 16 {
            self.byte_count += 64;
            let block = extract_block_16(@self.buffer, 0);
            self.h = blake2s_compress(self.h, self.byte_count, BoxTrait::new(block));
            self.buffer = ArrayTrait::new();
        }

        let mut i: usize = 0;

        // Process each input byte
        while i < input_len {
            let byte: u32 = input.at(i).unwrap().into();
            let shift: usize = self.pending_bytes.into() * 8;
            self.pending_word = self.pending_word | (byte * pow2_u32(shift));
            self.pending_bytes += 1;

            // If we have a complete word, add it to the buffer
            if self.pending_bytes == 4 {
                // Check if buffer is full BEFORE appending
                // We compress if buffer is full and we have more data to process
                if self.buffer.len() == 16 {
                    self.byte_count += 64;
                    let block = extract_block_16(@self.buffer, 0);
                    self.h = blake2s_compress(self.h, self.byte_count, BoxTrait::new(block));
                    self.buffer = ArrayTrait::new();
                }

                self.buffer.append(self.pending_word);
                self.pending_word = 0;
                self.pending_bytes = 0;
            }

            i += 1;
        };
    }

    /// Finalizes the hash and returns the digest.
    ///
    /// The returned array length equals the configured hash_length.
    fn finalize(ref self: Blake2sHasher) -> Array<u8> {
        // Add any pending partial word to the buffer
        if self.pending_bytes > 0 {
            self.buffer.append(self.pending_word);
        }

        // Calculate final byte count
        let buffer_words: u32 = self.buffer.len().try_into().unwrap();
        let pending: u32 = self.pending_bytes.into();
        // If pending_bytes > 0, we added a partial word, so byte count is:
        // byte_count + (buffer_words - 1) * 4 + pending_bytes
        // If pending_bytes == 0, byte count is:
        // byte_count + buffer_words * 4
        let final_byte_count = if self.pending_bytes > 0 {
            self.byte_count + (buffer_words - 1) * 4 + pending
        } else {
            self.byte_count + buffer_words * 4
        };

        // Pad buffer to 16 words
        while self.buffer.len() < 16 {
            self.buffer.append(0);
        };

        // Extract final block
        let block = extract_block_16(@self.buffer, 0);

        // Finalize
        self.h = blake2s_finalize(self.h, final_byte_count, BoxTrait::new(block));

        // Convert state to bytes (little-endian) and truncate to hash_length
        let [s0, s1, s2, s3, s4, s5, s6, s7] = self.h.unbox();
        let hash_len: usize = self.hash_length.into();

        // Extract bytes from each word (little-endian)
        let mut result: Array<u8> = ArrayTrait::new();
        append_word_bytes(ref result, s0, hash_len, 0);
        append_word_bytes(ref result, s1, hash_len, 4);
        append_word_bytes(ref result, s2, hash_len, 8);
        append_word_bytes(ref result, s3, hash_len, 12);
        append_word_bytes(ref result, s4, hash_len, 16);
        append_word_bytes(ref result, s5, hash_len, 20);
        append_word_bytes(ref result, s6, hash_len, 24);
        append_word_bytes(ref result, s7, hash_len, 28);

        result
    }

    /// Returns the number of bytes that have been processed.
    ///
    /// Note: If the hasher was initialized with a key, this does not
    /// include the key block in the count (matching reference behavior).
    fn count(self: @Blake2sHasher) -> u32 {
        let buffer_len: u32 = self.buffer.len().try_into().unwrap();
        let pending: u32 = (*self.pending_bytes).into();
        let raw_count = *self.byte_count + buffer_len * 4 + pending;
        if *self.is_keyed {
            // Subtract the key block if keyed
            if raw_count >= 64 {
                raw_count - 64
            } else {
                0
            }
        } else {
            raw_count
        }
    }
}

// ============================================================================
// Blake2b Implementation
// ============================================================================

/// Configuration parameters for Blake2b hashing.
///
/// Use the builder pattern to configure the hash:
/// ```
/// let params = Blake2bParams::new()
///     .hash_length(32)
///     .personal(@"myapp___________");
/// ```
#[derive(Drop, Clone)]
pub struct Blake2bParams {
    /// Output digest length (1-64 bytes, default: 64)
    hash_length: u8,
    /// Key length (0-64 bytes, default: 0)
    key_length: u8,
    /// Key bytes (up to 64 bytes as 8 u64 words)
    key: [u64; 8],
    /// Salt (16 bytes as two u64 words)
    salt: [u64; 2],
    /// Personalization (16 bytes as two u64 words)
    personal: [u64; 2],
    /// Fanout (0 = unlimited, 1 = sequential, default: 1)
    fanout: u8,
    /// Maximum tree depth (1 = sequential, 255 = unlimited, default: 1)
    max_depth: u8,
    /// Leaf maximum byte length (0 = unlimited, default: 0)
    leaf_length: u32,
    /// Node offset (default: 0)
    node_offset: u64,
    /// Node depth (0 = leaf, default: 0)
    node_depth: u8,
    /// Inner hash byte length (default: 0)
    inner_length: u8,
    /// Whether this is the last node in tree mode
    last_node: bool,
}

/// Trait for Blake2bParams builder pattern.
#[generate_trait]
pub impl Blake2bParamsImpl of Blake2bParamsTrait {
    /// Creates a new Blake2bParams with default settings.
    ///
    /// Default configuration:
    /// - hash_length: 64 bytes
    /// - No key
    /// - No salt
    /// - No personalization
    /// - Sequential mode (fanout=1, depth=1)
    fn new() -> Blake2bParams {
        Blake2bParams {
            hash_length: 64,
            key_length: 0,
            key: [0; 8],
            salt: [0; 2],
            personal: [0; 2],
            fanout: 1,
            max_depth: 1,
            leaf_length: 0,
            node_offset: 0,
            node_depth: 0,
            inner_length: 0,
            last_node: false,
        }
    }

    /// Sets the hash output length (1-64 bytes).
    ///
    /// # Panics
    /// Panics if length is 0 or greater than 64.
    fn hash_length(self: Blake2bParams, length: u8) -> Blake2bParams {
        assert(length >= 1 && length <= 64, 'hash_length must be 1-64');
        Blake2bParams { hash_length: length, ..self }
    }

    /// Sets a secret key for keyed hashing (MAC mode).
    ///
    /// The key can be up to 64 bytes. The key is provided as a ByteArray
    /// and will be padded to the block size internally.
    ///
    /// # Panics
    /// Panics if key length exceeds 64 bytes.
    fn key(self: Blake2bParams, key: @ByteArray) -> Blake2bParams {
        let key_len = key.len();
        assert(key_len <= 64, 'key must be <= 64 bytes');

        let key_words = bytes_to_u64_array_8(key);
        Blake2bParams { key_length: key_len.try_into().unwrap(), key: key_words, ..self }
    }

    /// Sets the salt value (up to 16 bytes).
    ///
    /// Salt is used for randomized hashing. If shorter than 16 bytes,
    /// it will be padded with zeros.
    ///
    /// # Panics
    /// Panics if salt exceeds 16 bytes.
    fn salt(self: Blake2bParams, salt: @ByteArray) -> Blake2bParams {
        assert(salt.len() <= 16, 'salt must be <= 16 bytes');
        let salt_words = bytes_to_u64_array_2(salt);
        Blake2bParams { salt: salt_words, ..self }
    }

    /// Sets the personalization string (up to 16 bytes).
    ///
    /// Personalization is used for domain separation. If shorter than
    /// 16 bytes, it will be padded with zeros.
    ///
    /// # Panics
    /// Panics if personalization exceeds 16 bytes.
    fn personal(self: Blake2bParams, personal: @ByteArray) -> Blake2bParams {
        assert(personal.len() <= 16, 'personal must be <= 16 bytes');
        let personal_words = bytes_to_u64_array_2(personal);
        Blake2bParams { personal: personal_words, ..self }
    }

    /// Sets the fanout for tree hashing.
    ///
    /// - 0 = unlimited
    /// - 1 = sequential (default)
    /// - 2-255 = specific fanout
    fn fanout(self: Blake2bParams, fanout: u8) -> Blake2bParams {
        Blake2bParams { fanout, ..self }
    }

    /// Sets the maximum tree depth.
    ///
    /// - 1 = sequential (default)
    /// - 255 = unlimited
    fn max_depth(self: Blake2bParams, depth: u8) -> Blake2bParams {
        assert(depth >= 1, 'max_depth must be >= 1');
        Blake2bParams { max_depth: depth, ..self }
    }

    /// Sets the maximum leaf length for tree hashing.
    fn leaf_length(self: Blake2bParams, length: u32) -> Blake2bParams {
        Blake2bParams { leaf_length: length, ..self }
    }

    /// Sets the node offset for tree hashing.
    fn node_offset(self: Blake2bParams, offset: u64) -> Blake2bParams {
        Blake2bParams { node_offset: offset, ..self }
    }

    /// Sets the node depth for tree hashing.
    fn node_depth(self: Blake2bParams, depth: u8) -> Blake2bParams {
        Blake2bParams { node_depth: depth, ..self }
    }

    /// Sets the inner hash length for tree hashing.
    fn inner_length(self: Blake2bParams, length: u8) -> Blake2bParams {
        assert(length <= 64, 'inner_length must be <= 64');
        Blake2bParams { inner_length: length, ..self }
    }

    /// Marks this node as the last in its row for tree hashing.
    fn last_node(self: Blake2bParams, last: bool) -> Blake2bParams {
        Blake2bParams { last_node: last, ..self }
    }

    /// Creates a Hasher for incremental hashing with these parameters.
    fn to_state(self: Blake2bParams) -> Blake2bHasher {
        let h = self.compute_initial_state();
        let mut state = Blake2bHasher {
            h,
            buffer: ArrayTrait::new(),
            pending_word: 0,
            pending_bytes: 0,
            byte_count: 0,
            hash_length: self.hash_length,
            last_node: self.last_node,
            is_keyed: self.key_length > 0,
        };

        // If keyed, the first block is the key padded to block size
        if self.key_length > 0 {
            // Add key as first block (padded to 128 bytes)
            let [k0, k1, k2, k3, k4, k5, k6, k7] = self.key;
            state.buffer.append(k0);
            state.buffer.append(k1);
            state.buffer.append(k2);
            state.buffer.append(k3);
            state.buffer.append(k4);
            state.buffer.append(k5);
            state.buffer.append(k6);
            state.buffer.append(k7);
            // Pad to 16 words (128 bytes)
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
            state.buffer.append(0);
        }

        state
    }

    /// Performs a one-shot hash with these parameters.
    fn hash(self: Blake2bParams, input: @ByteArray) -> Array<u8> {
        let mut state = self.to_state();
        state.update(input);
        state.finalize()
    }

    /// Creates a hasher, updates it with input, and returns it for chaining.
    ///
    /// This enables fluent API usage:
    /// ```
    /// let hash = Blake2bParams::new()
    ///     .hash_length(32)
    ///     .personal(@"myapp_______")
    ///     .update(@"input data")
    ///     .finalize();
    /// ```
    fn update(self: Blake2bParams, input: @ByteArray) -> Blake2bHasher {
        let mut state = self.to_state();
        state.update(input);
        state
    }
}

/// Internal methods for Blake2bParams
#[generate_trait]
impl Blake2bParamsInternal of Blake2bParamsInternalTrait {
    /// Computes the initial state by XORing IV with parameter block.
    fn compute_initial_state(self: @Blake2bParams) -> Blake2bState {
        let [iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7] = blake2b_const::IV;

        // Parameter block word 0: hash_length | key_length | fanout | depth | leaf_length
        let p0: u64 = (*self.hash_length).into()
            | ((*self.key_length).into() * 0x100)
            | ((*self.fanout).into() * 0x10000)
            | ((*self.max_depth).into() * 0x1000000)
            | ((*self.leaf_length).into() * 0x100000000);

        // Parameter block word 1: node_offset
        let p1: u64 = *self.node_offset;

        // Parameter block word 2: node_depth | inner_length | reserved (14 bytes)
        let p2: u64 = (*self.node_depth).into() | ((*self.inner_length).into() * 0x100);

        // Parameter block word 3: reserved
        let p3: u64 = 0;

        // Parameter block words 4-5: salt
        let [salt0, salt1] = *self.salt;

        // Parameter block words 6-7: personal
        let [pers0, pers1] = *self.personal;

        BoxTrait::new(
            [
                iv0 ^ p0,
                iv1 ^ p1,
                iv2 ^ p2,
                iv3 ^ p3,
                iv4 ^ salt0,
                iv5 ^ salt1,
                iv6 ^ pers0,
                iv7 ^ pers1,
            ],
        )
    }
}

/// Incremental hashing state for Blake2b.
///
/// Use this struct for streaming/incremental hashing. For the low-level
/// compression state type, use `Blake2bState` (which is `Box<[u64; 8]>`).
#[derive(Drop)]
pub struct Blake2bHasher {
    /// Current hash state (8 x 64-bit words)
    h: Blake2bState,
    /// Buffer for complete words (up to 16 x 64-bit words = 128 bytes)
    buffer: Array<u64>,
    /// Current word being built from input bytes
    pending_word: u64,
    /// Number of bytes in the pending word (0-7)
    pending_bytes: u8,
    /// Total bytes processed (not including pending or buffer)
    byte_count: u64,
    /// Configured hash output length
    hash_length: u8,
    /// Whether this is the last node in tree mode
    last_node: bool,
    /// Whether this state was initialized with a key
    is_keyed: bool,
}

/// Trait for Blake2bHasher operations.
#[generate_trait]
pub impl Blake2bHasherImpl of Blake2bHasherTrait {
    /// Creates a new Blake2bHasher with default parameters.
    fn new() -> Blake2bHasher {
        Blake2bParamsImpl::to_state(Blake2bParamsImpl::new())
    }

    /// Updates the hash state with additional input data.
    fn update(ref self: Blake2bHasher, input: @ByteArray) {
        let input_len = input.len();
        if input_len == 0 {
            return;
        }

        // If buffer is full (e.g., from keyed hashing) and we have new data,
        // compress the buffer first
        if self.buffer.len() == 16 {
            self.byte_count += 128;
            let block = extract_block_16_u64(@self.buffer, 0);
            self.h = blake2b_compress(self.h, self.byte_count, BoxTrait::new(block));
            self.buffer = ArrayTrait::new();
        }

        let mut i: usize = 0;

        // Process each input byte
        while i < input_len {
            let byte: u64 = input.at(i).unwrap().into();
            let shift: usize = self.pending_bytes.into() * 8;
            self.pending_word = self.pending_word | (byte * pow2_u64(shift));
            self.pending_bytes += 1;

            // If we have a complete word (8 bytes), add it to the buffer
            if self.pending_bytes == 8 {
                // Check if buffer is full BEFORE appending
                // We compress if buffer is full and we have more data to process
                if self.buffer.len() == 16 {
                    self.byte_count += 128;
                    let block = extract_block_16_u64(@self.buffer, 0);
                    self.h = blake2b_compress(self.h, self.byte_count, BoxTrait::new(block));
                    self.buffer = ArrayTrait::new();
                }

                self.buffer.append(self.pending_word);
                self.pending_word = 0;
                self.pending_bytes = 0;
            }

            i += 1;
        };
    }

    /// Finalizes the hash and returns the digest.
    ///
    /// The returned array length equals the configured hash_length.
    fn finalize(ref self: Blake2bHasher) -> Array<u8> {
        // Add any pending partial word to the buffer
        if self.pending_bytes > 0 {
            self.buffer.append(self.pending_word);
        }

        // Calculate final byte count
        let buffer_words: u64 = self.buffer.len().try_into().unwrap();
        let pending: u64 = self.pending_bytes.into();
        // If pending_bytes > 0, we added a partial word, so byte count is:
        // byte_count + (buffer_words - 1) * 8 + pending_bytes
        // If pending_bytes == 0, byte count is:
        // byte_count + buffer_words * 8
        let final_byte_count = if self.pending_bytes > 0 {
            self.byte_count + (buffer_words - 1) * 8 + pending
        } else {
            self.byte_count + buffer_words * 8
        };

        // Pad buffer to 16 words
        while self.buffer.len() < 16 {
            self.buffer.append(0);
        };

        // Extract final block
        let block = extract_block_16_u64(@self.buffer, 0);

        // Finalize
        self.h = blake2b_finalize(self.h, final_byte_count, BoxTrait::new(block));

        // Convert state to bytes (little-endian) and truncate to hash_length
        let [s0, s1, s2, s3, s4, s5, s6, s7] = self.h.unbox();
        let hash_len: usize = self.hash_length.into();

        // Extract bytes from each word (little-endian)
        let mut result: Array<u8> = ArrayTrait::new();
        append_word_bytes_u64(ref result, s0, hash_len, 0);
        append_word_bytes_u64(ref result, s1, hash_len, 8);
        append_word_bytes_u64(ref result, s2, hash_len, 16);
        append_word_bytes_u64(ref result, s3, hash_len, 24);
        append_word_bytes_u64(ref result, s4, hash_len, 32);
        append_word_bytes_u64(ref result, s5, hash_len, 40);
        append_word_bytes_u64(ref result, s6, hash_len, 48);
        append_word_bytes_u64(ref result, s7, hash_len, 56);

        result
    }

    /// Returns the number of bytes that have been processed.
    ///
    /// Note: If the hasher was initialized with a key, this does not
    /// include the key block in the count (matching reference behavior).
    fn count(self: @Blake2bHasher) -> u64 {
        let buffer_len: u64 = self.buffer.len().try_into().unwrap();
        let pending: u64 = (*self.pending_bytes).into();
        let raw_count = *self.byte_count + buffer_len * 8 + pending;
        if *self.is_keyed {
            // Subtract the key block if keyed
            if raw_count >= 128 {
                raw_count - 128
            } else {
                0
            }
        } else {
            raw_count
        }
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Computes the Blake2s-256 hash of the input.
///
/// This is equivalent to `Blake2sParams::new().hash(input)`.
///
/// # Examples
/// ```
/// use core::blake::blake2s;
/// let hash = blake2s(@"hello world");
/// assert!(hash.len() == 32);
/// ```
pub fn blake2s(input: @ByteArray) -> Array<u8> {
    Blake2sParamsImpl::hash(Blake2sParamsImpl::new(), input)
}

/// Computes the Blake2b-512 hash of the input.
///
/// This is equivalent to `Blake2bParams::new().hash(input)`.
///
/// # Examples
/// ```
/// use core::blake::blake2b;
/// let hash = blake2b(@"hello world");
/// assert!(hash.len() == 64);
/// ```
pub fn blake2b(input: @ByteArray) -> Array<u8> {
    Blake2bParamsImpl::hash(Blake2bParamsImpl::new(), input)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Converts a ByteArray to an array of 2 u32 words (little-endian).
fn bytes_to_u32_array_2(bytes: @ByteArray) -> [u32; 2] {
    let len = bytes.len();
    let mut words: Array<u32> = ArrayTrait::new();

    let mut word_idx: usize = 0;
    while word_idx < 2 {
        let mut word: u32 = 0;
        let mut byte_idx: usize = 0;
        while byte_idx < 4 {
            let global_idx = word_idx * 4 + byte_idx;
            if global_idx < len {
                let byte: u32 = bytes.at(global_idx).unwrap().into();
                word = word | (byte * pow2_u32(byte_idx * 8));
            }
            byte_idx += 1;
        };
        words.append(word);
        word_idx += 1;
    };

    [*words[0], *words[1]]
}

/// Converts a ByteArray to an array of 8 u32 words (little-endian).
fn bytes_to_u32_array_8(bytes: @ByteArray) -> [u32; 8] {
    let len = bytes.len();
    let mut words: Array<u32> = ArrayTrait::new();

    let mut word_idx: usize = 0;
    while word_idx < 8 {
        let mut word: u32 = 0;
        let mut byte_idx: usize = 0;
        while byte_idx < 4 {
            let global_idx = word_idx * 4 + byte_idx;
            if global_idx < len {
                let byte: u32 = bytes.at(global_idx).unwrap().into();
                word = word | (byte * pow2_u32(byte_idx * 8));
            }
            byte_idx += 1;
        };
        words.append(word);
        word_idx += 1;
    };

    [*words[0], *words[1], *words[2], *words[3], *words[4], *words[5], *words[6], *words[7]]
}

/// Converts a ByteArray to an array of 2 u64 words (little-endian).
fn bytes_to_u64_array_2(bytes: @ByteArray) -> [u64; 2] {
    let len = bytes.len();
    let mut words: Array<u64> = ArrayTrait::new();

    let mut word_idx: usize = 0;
    while word_idx < 2 {
        let mut word: u64 = 0;
        let mut byte_idx: usize = 0;
        while byte_idx < 8 {
            let global_idx = word_idx * 8 + byte_idx;
            if global_idx < len {
                let byte: u64 = bytes.at(global_idx).unwrap().into();
                word = word | (byte * pow2_u64(byte_idx * 8));
            }
            byte_idx += 1;
        };
        words.append(word);
        word_idx += 1;
    };

    [*words[0], *words[1]]
}

/// Converts a ByteArray to an array of 8 u64 words (little-endian).
fn bytes_to_u64_array_8(bytes: @ByteArray) -> [u64; 8] {
    let len = bytes.len();
    let mut words: Array<u64> = ArrayTrait::new();

    let mut word_idx: usize = 0;
    while word_idx < 8 {
        let mut word: u64 = 0;
        let mut byte_idx: usize = 0;
        while byte_idx < 8 {
            let global_idx = word_idx * 8 + byte_idx;
            if global_idx < len {
                let byte: u64 = bytes.at(global_idx).unwrap().into();
                word = word | (byte * pow2_u64(byte_idx * 8));
            }
            byte_idx += 1;
        };
        words.append(word);
        word_idx += 1;
    };

    [*words[0], *words[1], *words[2], *words[3], *words[4], *words[5], *words[6], *words[7]]
}

/// Extracts a 16-word block from a u32 array starting at the given offset.
fn extract_block_16(arr: @Array<u32>, offset: usize) -> [u32; 16] {
    [
        *arr[offset],
        *arr[offset + 1],
        *arr[offset + 2],
        *arr[offset + 3],
        *arr[offset + 4],
        *arr[offset + 5],
        *arr[offset + 6],
        *arr[offset + 7],
        *arr[offset + 8],
        *arr[offset + 9],
        *arr[offset + 10],
        *arr[offset + 11],
        *arr[offset + 12],
        *arr[offset + 13],
        *arr[offset + 14],
        *arr[offset + 15],
    ]
}

/// Extracts a 16-word block from a u64 array starting at the given offset.
fn extract_block_16_u64(arr: @Array<u64>, offset: usize) -> [u64; 16] {
    [
        *arr[offset],
        *arr[offset + 1],
        *arr[offset + 2],
        *arr[offset + 3],
        *arr[offset + 4],
        *arr[offset + 5],
        *arr[offset + 6],
        *arr[offset + 7],
        *arr[offset + 8],
        *arr[offset + 9],
        *arr[offset + 10],
        *arr[offset + 11],
        *arr[offset + 12],
        *arr[offset + 13],
        *arr[offset + 14],
        *arr[offset + 15],
    ]
}

/// Returns 2^n for u32.
fn pow2_u32(n: usize) -> u32 {
    if n == 0 {
        1
    } else if n == 8 {
        0x100
    } else if n == 16 {
        0x10000
    } else if n == 24 {
        0x1000000
    } else {
        let mut result: u32 = 1;
        let mut i: usize = 0;
        while i < n {
            result *= 2;
            i += 1;
        };
        result
    }
}

/// Returns 2^n for u64.
fn pow2_u64(n: usize) -> u64 {
    if n == 0 {
        1
    } else if n == 8 {
        0x100
    } else if n == 16 {
        0x10000
    } else if n == 24 {
        0x1000000
    } else if n == 32 {
        0x100000000
    } else if n == 40 {
        0x10000000000
    } else if n == 48 {
        0x1000000000000
    } else if n == 56 {
        0x100000000000000
    } else {
        let mut result: u64 = 1;
        let mut i: usize = 0;
        while i < n {
            result *= 2;
            i += 1;
        };
        result
    }
}

/// Appends bytes from a u32 word to the result array, respecting hash_len limit.
/// word_offset is the byte offset of this word in the overall output.
fn append_word_bytes(ref result: Array<u8>, word: u32, hash_len: usize, word_offset: usize) {
    if word_offset < hash_len {
        result.append((word & 0xFF).try_into().unwrap());
    }
    if word_offset + 1 < hash_len {
        result.append(((word / 0x100) & 0xFF).try_into().unwrap());
    }
    if word_offset + 2 < hash_len {
        result.append(((word / 0x10000) & 0xFF).try_into().unwrap());
    }
    if word_offset + 3 < hash_len {
        result.append(((word / 0x1000000) & 0xFF).try_into().unwrap());
    }
}

/// Appends bytes from a u64 word to the result array, respecting hash_len limit.
/// word_offset is the byte offset of this word in the overall output.
fn append_word_bytes_u64(ref result: Array<u8>, word: u64, hash_len: usize, word_offset: usize) {
    if word_offset < hash_len {
        result.append((word & 0xFF).try_into().unwrap());
    }
    if word_offset + 1 < hash_len {
        result.append(((word / 0x100) & 0xFF).try_into().unwrap());
    }
    if word_offset + 2 < hash_len {
        result.append(((word / 0x10000) & 0xFF).try_into().unwrap());
    }
    if word_offset + 3 < hash_len {
        result.append(((word / 0x1000000) & 0xFF).try_into().unwrap());
    }
    if word_offset + 4 < hash_len {
        result.append(((word / 0x100000000) & 0xFF).try_into().unwrap());
    }
    if word_offset + 5 < hash_len {
        result.append(((word / 0x10000000000) & 0xFF).try_into().unwrap());
    }
    if word_offset + 6 < hash_len {
        result.append(((word / 0x1000000000000) & 0xFF).try_into().unwrap());
    }
    if word_offset + 7 < hash_len {
        result.append(((word / 0x100000000000000) & 0xFF).try_into().unwrap());
    }
}
