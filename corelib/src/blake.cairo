//! Blake2 cryptographic hash functions.
//!
//! # Examples
//!
//! Simple one-shot hashing with Array:
//! ```
//! use core::blake::blake2s;
//! let input: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f];  // "hello"
//! let state = blake2s(input);
//! ```
//!
//! Simple one-shot hashing with ByteArray:
//! ```
//! use core::blake::blake2s_bytearray;
//! let state = blake2s_bytearray(@"hello world");
//! ```
//!
//! Builder pattern with personalization:
//! ```
//! use core::blake::{Blake2bParams, Blake2bParamsTrait};
//! // Personalization as two little-endian u64 words
//! let input: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f];
//! let state = Blake2bParams::new()
//!     .hash_length(32)
//!     .personal([0x7070615f79706d79, 0x5f5f5f5f5f5f5f5f])
//!     .hash(input);
//! ```
//!
//! Fluent API with chaining:
//! ```
//! use core::blake::{Blake2sParams, Blake2sParamsTrait, Blake2sHasherTrait};
//! // Personalization as two little-endian u32 words
//! let input: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f];
//! let state = Blake2sParams::new()
//!     .hash_length(16)
//!     .personal([0x7061796d, 0x5f5f5f70])
//!     .update(input)
//!     .finalize();
//! ```

use crate::array::{ArrayTrait};
use crate::box::BoxTrait;
use crate::byte_array::{ByteArrayTrait, ToByteSpanTrait};
use crate::iter::IntoIterator;
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
/// let input: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f];
/// let state = Blake2sParams::new()
///     .hash_length(16)
///     .personal([0x7061796d, 0x5f5f5f70])
///     .hash(input);
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
    /// The key is provided as 8 little-endian u32 words (32 bytes total).
    /// Unused bytes should be zero-padded. The actual key length in bytes
    /// must be provided separately.
    ///
    /// # Panics
    /// Panics if key_length exceeds 32 bytes.
    fn key(self: Blake2sParams, key: [u32; 8], key_length: u8) -> Blake2sParams {
        assert(key_length <= 32, 'key must be <= 32 bytes');
        Blake2sParams { key_length, key, ..self }
    }

    /// Sets the salt value (8 bytes as two little-endian u32 words).
    ///
    /// Salt is used for randomized hashing.
    fn salt(self: Blake2sParams, salt: [u32; 2]) -> Blake2sParams {
        Blake2sParams { salt, ..self }
    }

    /// Sets the personalization string (8 bytes as two little-endian u32 words).
    ///
    /// Personalization is used for domain separation.
    fn personal(self: Blake2sParams, personal: [u32; 2]) -> Blake2sParams {
        Blake2sParams { personal, ..self }
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

    /// Performs a one-shot hash from input array.
    ///
    /// Returns the raw hash state.
    fn hash(self: Blake2sParams, input: Array<u8>) -> Blake2sState {
        let mut state = self.to_state();
        state.update(input);
        state.finalize()
    }

    /// Performs a one-shot hash with ByteArray input.
    ///
    /// Returns the raw hash state.
    fn hash_bytearray(self: Blake2sParams, input: @ByteArray) -> Blake2sState {
        let mut state = self.to_state();
        state.update_bytearray(input);
        state.finalize()
    }

    /// Creates a hasher, updates it with input, and returns it for chaining.
    ///
    /// This enables fluent API usage:
    /// ```
    /// let input: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f];
    /// let state = Blake2sParams::new()
    ///     .hash_length(16)
    ///     .personal([0x7061796d, 0x5f5f5f70])
    ///     .update(input)
    ///     .finalize();
    /// ```
    fn update(self: Blake2sParams, input: Array<u8>) -> Blake2sHasher {
        let mut state = self.to_state();
        state.update(input);
        state
    }

    /// Creates a hasher, updates it with ByteArray input, and returns it for chaining.
    fn update_bytearray(self: Blake2sParams, input: @ByteArray) -> Blake2sHasher {
        let mut state = self.to_state();
        state.update_bytearray(input);
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
    fn update(ref self: Blake2sHasher, input: Array<u8>) {
        if input.len() == 0 {
            return;
        }

        // If buffer is full (e.g., from keyed hashing) and we have new data,
        // compress the buffer first
        if self.buffer.len() == 16 {
            self.byte_count += 64;
            let block = array_to_block_16(@self.buffer);
            self.h = blake2s_compress(self.h, self.byte_count, BoxTrait::new(block));
            self.buffer = ArrayTrait::new();
        }

        // Process each input byte using span iteration (more efficient than indexing)
        let mut input_span = input.span();
        while let Option::Some(byte_ref) = input_span.pop_front() {
            let byte: u32 = (*byte_ref).into();
            self.pending_word = self.pending_word | (byte * byte_shift_u32(self.pending_bytes));
            self.pending_bytes += 1;

            // If we have a complete word, add it to the buffer
            if self.pending_bytes == 4 {
                // Check if buffer is full BEFORE appending
                // We compress if buffer is full and we have more data to process
                if self.buffer.len() == 16 {
                    self.byte_count += 64;
                    let block = array_to_block_16(@self.buffer);
                    self.h = blake2s_compress(self.h, self.byte_count, BoxTrait::new(block));
                    self.buffer = ArrayTrait::new();
                }

                self.buffer.append(self.pending_word);
                self.pending_word = 0;
                self.pending_bytes = 0;
            }
        };
    }

    /// Updates the hash state with ByteArray input.
    fn update_bytearray(ref self: Blake2sHasher, input: @ByteArray) {
        let input_len = input.len();
        if input_len == 0 {
            return;
        }

        // If buffer is full (e.g., from keyed hashing) and we have new data,
        // compress the buffer first
        if self.buffer.len() == 16 {
            self.byte_count += 64;
            let block = array_to_block_16(@self.buffer);
            self.h = blake2s_compress(self.h, self.byte_count, BoxTrait::new(block));
            self.buffer = ArrayTrait::new();
        }

        let mut i: usize = 0;

        // Process each input byte
        while i < input_len {
            let byte: u32 = input.at(i).unwrap().into();
            self.pending_word = self.pending_word | (byte * byte_shift_u32(self.pending_bytes));
            self.pending_bytes += 1;

            // If we have a complete word, add it to the buffer
            if self.pending_bytes == 4 {
                // Check if buffer is full BEFORE appending
                // We compress if buffer is full and we have more data to process
                if self.buffer.len() == 16 {
                    self.byte_count += 64;
                    let block = array_to_block_16(@self.buffer);
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

    /// Updates the hash state with a single u32 value in little-endian byte order.
    ///
    /// This is optimized for small fixed-size updates and avoids the overhead
    /// of creating an Array<u8>.
    ///
    /// # Examples
    /// ```
    /// let mut hasher = Blake2sHasherTrait::new();
    /// hasher.update_u32_le(0xDEADBEEF);  // Adds bytes [0xEF, 0xBE, 0xAD, 0xDE]
    /// ```
    #[inline(always)]
    fn update_u32_le(ref self: Blake2sHasher, value: u32) {
        // If buffer is full, compress first
        if self.buffer.len() == 16 {
            self.byte_count += 64;
            let block = array_to_block_16(@self.buffer);
            self.h = blake2s_compress(self.h, self.byte_count, BoxTrait::new(block));
            self.buffer = ArrayTrait::new();
        }

        // Extract 4 bytes from the u32 in little-endian order
        let b0: u32 = value & 0xFF;
        let b1: u32 = (value / 0x100) & 0xFF;
        let b2: u32 = (value / 0x10000) & 0xFF;
        let b3: u32 = (value / 0x1000000) & 0xFF;

        // Process based on current pending_bytes alignment
        if self.pending_bytes == 0 {
            // Aligned: this completes exactly one word
            let word = b0 | (b1 * 0x100) | (b2 * 0x10000) | (b3 * 0x1000000);
            // Check buffer before appending
            if self.buffer.len() == 16 {
                self.byte_count += 64;
                let block = array_to_block_16(@self.buffer);
                self.h = blake2s_compress(self.h, self.byte_count, BoxTrait::new(block));
                self.buffer = ArrayTrait::new();
            }
            self.buffer.append(word);
            // pending_bytes stays 0, pending_word stays 0
        } else {
            // Unaligned: process byte by byte
            let bytes: [u8; 4] = [
                (value & 0xFF).try_into().unwrap(),
                ((value / 0x100) & 0xFF).try_into().unwrap(),
                ((value / 0x10000) & 0xFF).try_into().unwrap(),
                ((value / 0x1000000) & 0xFF).try_into().unwrap(),
            ];
            let mut span = bytes.span();
            while let Option::Some(byte_ref) = span.pop_front() {
                let byte: u32 = (*byte_ref).into();
                self.pending_word = self.pending_word | (byte * byte_shift_u32(self.pending_bytes));
                self.pending_bytes += 1;
                if self.pending_bytes == 4 {
                    if self.buffer.len() == 16 {
                        self.byte_count += 64;
                        let block = array_to_block_16(@self.buffer);
                        self.h = blake2s_compress(self.h, self.byte_count, BoxTrait::new(block));
                        self.buffer = ArrayTrait::new();
                    }
                    self.buffer.append(self.pending_word);
                    self.pending_word = 0;
                    self.pending_bytes = 0;
                }
            };
        }
    }

    /// Finalizes the hash and returns the raw state.
    fn finalize(ref self: Blake2sHasher) -> Blake2sState {
        // Add any pending partial word to the buffer
        if self.pending_bytes > 0 {
            self.buffer.append(self.pending_word);
        }

        // Calculate final byte count
        let buffer_words: u32 = self.buffer.len();
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
        let block = array_to_block_16(@self.buffer);

        // Finalize and return state
        blake2s_finalize(self.h, final_byte_count, BoxTrait::new(block))
    }

    /// Returns the number of bytes that have been processed.
    ///
    /// Note: If the hasher was initialized with a key, this does not
    /// include the key block in the count (matching reference behavior).
    fn count(self: @Blake2sHasher) -> u32 {
        let buffer_len: u32 = self.buffer.len();
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
/// let input: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f];
/// let state = Blake2bParams::new()
///     .hash_length(32)
///     .personal([0x7070615f79706d79, 0x5f5f5f5f5f5f5f5f])
///     .hash(input);
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
    /// The key is provided as 8 little-endian u64 words (64 bytes total).
    /// Unused bytes should be zero-padded. The actual key length in bytes
    /// must be provided separately.
    ///
    /// # Panics
    /// Panics if key_length exceeds 64 bytes.
    fn key(self: Blake2bParams, key: [u64; 8], key_length: u8) -> Blake2bParams {
        assert(key_length <= 64, 'key must be <= 64 bytes');
        Blake2bParams { key_length, key, ..self }
    }

    /// Sets the salt value (16 bytes as two little-endian u64 words).
    ///
    /// Salt is used for randomized hashing.
    fn salt(self: Blake2bParams, salt: [u64; 2]) -> Blake2bParams {
        Blake2bParams { salt, ..self }
    }

    /// Sets the personalization string (16 bytes as two little-endian u64 words).
    ///
    /// Personalization is used for domain separation.
    fn personal(self: Blake2bParams, personal: [u64; 2]) -> Blake2bParams {
        Blake2bParams { personal, ..self }
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

    /// Performs a one-shot hash with input array.
    ///
    /// Returns the raw hash state. Use `hash_bytearray` for ByteArray input.
    fn hash(self: Blake2bParams, input: Array<u8>) -> Blake2bState {
        let mut state = self.to_state();
        state.update(input);
        state.finalize()
    }

    /// Performs a one-shot hash with ByteArray input.
    ///
    /// Returns the raw hash state.
    fn hash_bytearray(self: Blake2bParams, input: @ByteArray) -> Blake2bState {
        let mut state = self.to_state();
        state.update_bytearray(input);
        state.finalize()
    }

    /// Creates a hasher, updates it with input, and returns it for chaining.
    ///
    /// This enables fluent API usage:
    /// ```
    /// let input: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f];
    /// let state = Blake2bParams::new()
    ///     .hash_length(32)
    ///     .personal([0x7070615f79706d79, 0x5f5f5f5f5f5f5f5f])
    ///     .update(input)
    ///     .finalize();
    /// ```
    fn update(self: Blake2bParams, input: Array<u8>) -> Blake2bHasher {
        let mut state = self.to_state();
        state.update(input);
        state
    }

    /// Creates a hasher, updates it with ByteArray input, and returns it for chaining.
    fn update_bytearray(self: Blake2bParams, input: @ByteArray) -> Blake2bHasher {
        let mut state = self.to_state();
        state.update_bytearray(input);
        state
    }
}

/// Methods for computing initial state from Blake2bParams.
/// Useful for pre-computing state when hashing many messages with the same parameters.
#[generate_trait]
pub impl Blake2bParamsStateImpl of Blake2bParamsStateTrait {
    /// Computes the initial state by XORing IV with parameter block.
    /// This can be used to pre-compute the initial state for repeated hashing
    /// with the same parameters (e.g., same personalization and hash length).
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
    /// Whether this state was initialized with a key
    is_keyed: bool,
}

/// Manual Clone implementation for Blake2bHasher.
/// This allows cloning a mid-state hasher for batch hashing optimizations.
pub impl Blake2bHasherClone of Clone<Blake2bHasher> {
    fn clone(self: @Blake2bHasher) -> Blake2bHasher {
        Blake2bHasher {
            h: *self.h,
            buffer: self.buffer.clone(),
            pending_word: *self.pending_word,
            pending_bytes: *self.pending_bytes,
            byte_count: *self.byte_count,
            hash_length: *self.hash_length,
            is_keyed: *self.is_keyed,
        }
    }
}

/// Trait for Blake2bHasher operations.
#[generate_trait]
pub impl Blake2bHasherImpl of Blake2bHasherTrait {
    /// Creates a new Blake2bHasher with default parameters.
    fn new() -> Blake2bHasher {
        Blake2bParamsImpl::to_state(Blake2bParamsImpl::new())
    }

    /// Clones the hasher state for batch hashing optimizations.
    /// This allows pre-computing a base state and cloning it for each hash
    /// when hashing multiple messages with the same prefix.
    fn clone_state(self: @Blake2bHasher) -> Blake2bHasher {
        Blake2bHasher {
            h: *self.h,
            buffer: self.buffer.clone(),
            pending_word: *self.pending_word,
            pending_bytes: *self.pending_bytes,
            byte_count: *self.byte_count,
            hash_length: *self.hash_length,
            is_keyed: *self.is_keyed,
        }
    }

    /// Updates the hash state with additional input data.
    fn update(ref self: Blake2bHasher, input: Array<u8>) {
        if input.len() == 0 {
            return;
        }

        // If buffer is full (e.g., from keyed hashing) and we have new data,
        // compress the buffer first
        if self.buffer.len() == 16 {
            self.byte_count += 128;
            let block = array_to_block_16_u64(@self.buffer);
            self.h = blake2b_compress(self.h, self.byte_count, BoxTrait::new(block));
            self.buffer = ArrayTrait::new();
        }

        // Process each input byte using span iteration (more efficient than indexing)
        let mut input_span = input.span();
        while let Option::Some(byte_ref) = input_span.pop_front() {
            let byte: u64 = (*byte_ref).into();
            self.pending_word = self.pending_word | (byte * byte_shift_u64(self.pending_bytes));
            self.pending_bytes += 1;

            // If we have a complete word (8 bytes), add it to the buffer
            if self.pending_bytes == 8 {
                // Check if buffer is full BEFORE appending
                // We compress if buffer is full and we have more data to process
                if self.buffer.len() == 16 {
                    self.byte_count += 128;
                    let block = array_to_block_16_u64(@self.buffer);
                    self.h = blake2b_compress(self.h, self.byte_count, BoxTrait::new(block));
                    self.buffer = ArrayTrait::new();
                }

                self.buffer.append(self.pending_word);
                self.pending_word = 0;
                self.pending_bytes = 0;
            }
        };
    }

    /// Updates the hash state with ByteArray input.
    fn update_bytearray(ref self: Blake2bHasher, input: @ByteArray) {
        if input.len() == 0 {
            return;
        }

        // If buffer is full (e.g., from keyed hashing) and we have new data,
        // compress the buffer first
        if self.buffer.len() == 16 {
            self.byte_count += 128;
            let block = array_to_block_16_u64(@self.buffer);
            self.h = blake2b_compress(self.h, self.byte_count, BoxTrait::new(block));
            self.buffer = ArrayTrait::new();
        }

        // Process each input byte using span iteration (more efficient than indexing)
        let mut input_iter = input.span().into_iter();
        while let Option::Some(byte) = input_iter.next() {
            let byte_u64: u64 = byte.into();
            self.pending_word = self.pending_word | (byte_u64 * byte_shift_u64(self.pending_bytes));
            self.pending_bytes += 1;

            // If we have a complete word (8 bytes), add it to the buffer
            if self.pending_bytes == 8 {
                // Check if buffer is full BEFORE appending
                // We compress if buffer is full and we have more data to process
                if self.buffer.len() == 16 {
                    self.byte_count += 128;
                    let block = array_to_block_16_u64(@self.buffer);
                    self.h = blake2b_compress(self.h, self.byte_count, BoxTrait::new(block));
                    self.buffer = ArrayTrait::new();
                }

                self.buffer.append(self.pending_word);
                self.pending_word = 0;
                self.pending_bytes = 0;
            }
        };
    }

    /// Updates the hash state with a single u32 value in little-endian byte order.
    ///
    /// This is optimized for small fixed-size updates (like Equihash 4-byte indices)
    /// and avoids the overhead of creating an Array<u8>.
    ///
    /// # Examples
    /// ```
    /// let mut hasher = Blake2bHasherTrait::new();
    /// hasher.update_u32_le(0xDEADBEEF);  // Adds bytes [0xEF, 0xBE, 0xAD, 0xDE]
    /// ```
    #[inline(always)]
    fn update_u32_le(ref self: Blake2bHasher, value: u32) {
        // If buffer is full, compress first
        if self.buffer.len() == 16 {
            self.byte_count += 128;
            let block = array_to_block_16_u64(@self.buffer);
            self.h = blake2b_compress(self.h, self.byte_count, BoxTrait::new(block));
            self.buffer = ArrayTrait::new();
        }

        // Extract 4 bytes from the u32 in little-endian order
        let b0: u64 = (value & 0xFF).into();
        let b1: u64 = ((value / 0x100) & 0xFF).into();
        let b2: u64 = ((value / 0x10000) & 0xFF).into();
        let b3: u64 = ((value / 0x1000000) & 0xFF).into();

        // Process based on current pending_bytes alignment
        // This is optimized for the common case where pending_bytes is 0 or 4
        if self.pending_bytes == 0 {
            // Aligned: pack all 4 bytes into pending_word directly
            self.pending_word = b0 | (b1 * 0x100) | (b2 * 0x10000) | (b3 * 0x1000000);
            self.pending_bytes = 4;
        } else if self.pending_bytes == 4 {
            // Half-aligned: complete current word and start new one
            self.pending_word = self.pending_word
                | (b0 * 0x100000000)
                | (b1 * 0x10000000000)
                | (b2 * 0x1000000000000)
                | (b3 * 0x100000000000000);
            // Word complete, add to buffer
            if self.buffer.len() == 16 {
                self.byte_count += 128;
                let block = array_to_block_16_u64(@self.buffer);
                self.h = blake2b_compress(self.h, self.byte_count, BoxTrait::new(block));
                self.buffer = ArrayTrait::new();
            }
            self.buffer.append(self.pending_word);
            self.pending_word = 0;
            self.pending_bytes = 0;
        } else {
            // Unaligned: process byte by byte (rare case)
            let bytes: [u8; 4] = [
                (value & 0xFF).try_into().unwrap(),
                ((value / 0x100) & 0xFF).try_into().unwrap(),
                ((value / 0x10000) & 0xFF).try_into().unwrap(),
                ((value / 0x1000000) & 0xFF).try_into().unwrap(),
            ];
            let mut span = bytes.span();
            while let Option::Some(byte_ref) = span.pop_front() {
                let byte: u64 = (*byte_ref).into();
                self.pending_word = self.pending_word | (byte * byte_shift_u64(self.pending_bytes));
                self.pending_bytes += 1;
                if self.pending_bytes == 8 {
                    if self.buffer.len() == 16 {
                        self.byte_count += 128;
                        let block = array_to_block_16_u64(@self.buffer);
                        self.h = blake2b_compress(self.h, self.byte_count, BoxTrait::new(block));
                        self.buffer = ArrayTrait::new();
                    }
                    self.buffer.append(self.pending_word);
                    self.pending_word = 0;
                    self.pending_bytes = 0;
                }
            };
        }
    }

    /// Finalizes the hash and returns the raw state.
    fn finalize(ref self: Blake2bHasher) -> Blake2bState {
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
        let block = array_to_block_16_u64(@self.buffer);

        // Finalize and return state
        blake2b_finalize(self.h, final_byte_count, BoxTrait::new(block))
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
/// let input: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f];
/// let state = blake2s(input);
/// ```
pub fn blake2s(input: Array<u8>) -> Blake2sState {
    Blake2sParamsImpl::hash(Blake2sParamsImpl::new(), input)
}

/// Computes the Blake2s-256 hash of ByteArray input.
///
/// This is equivalent to `Blake2sParams::new().hash_bytearray(input)`.
///
/// # Examples
/// ```
/// use core::blake::blake2s_bytearray;
/// let state = blake2s_bytearray(@"hello world");
/// ```
pub fn blake2s_bytearray(input: @ByteArray) -> Blake2sState {
    Blake2sParamsImpl::hash_bytearray(Blake2sParamsImpl::new(), input)
}

/// Computes the Blake2b-512 hash of the input.
///
/// This is equivalent to `Blake2bParams::new().hash(input)`.
///
/// # Examples
/// ```
/// use core::blake::blake2b;
/// let input: Array<u8> = array![0x68, 0x65, 0x6c, 0x6c, 0x6f];
/// let state = blake2b(input);
/// ```
pub fn blake2b(input: Array<u8>) -> Blake2bState {
    Blake2bParamsImpl::hash(Blake2bParamsImpl::new(), input)
}

/// Computes the Blake2b-512 hash of ByteArray input.
///
/// This is equivalent to `Blake2bParams::new().hash_bytearray(input)`.
///
/// # Examples
/// ```
/// use core::blake::blake2b_bytearray;
/// let state = blake2b_bytearray(@"hello world");
/// ```
pub fn blake2b_bytearray(input: @ByteArray) -> Blake2bState {
    Blake2bParamsImpl::hash_bytearray(Blake2bParamsImpl::new(), input)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Converts a 16-element u32 array to a fixed-size array.
/// Uses try_into for efficient conversion from span to fixed array.
#[inline(always)]
fn array_to_block_16(arr: @Array<u32>) -> [u32; 16] {
    let block_ref: @Box<[u32; 16]> = arr.span().try_into().unwrap();
    block_ref.unbox()
}

/// Converts a 16-element u64 array to a fixed-size array.
/// Uses try_into for efficient conversion from span to fixed array.
#[inline(always)]
fn array_to_block_16_u64(arr: @Array<u64>) -> [u64; 16] {
    let block_ref: @Box<[u64; 16]> = arr.span().try_into().unwrap();
    block_ref.unbox()
}

/// Returns 2^(byte_pos * 8) for u32 using lookup table.
/// Takes byte position directly (0-3) instead of bit shift amount.
#[inline(always)]
fn byte_shift_u32(byte_pos: u8) -> u32 {
    let lookup: [u32; 4] = [
        0x1,        // 2^0  (byte 0)
        0x100,      // 2^8  (byte 1)
        0x10000,    // 2^16 (byte 2)
        0x1000000,  // 2^24 (byte 3)
    ];
    let idx: usize = byte_pos.into();
    *lookup.span()[idx]
}

/// Returns 2^(byte_pos * 8) for u64 using lookup table.
/// Takes byte position directly (0-7) instead of bit shift amount.
#[inline(always)]
fn byte_shift_u64(byte_pos: u8) -> u64 {
    let lookup: [u64; 8] = [
        0x1,                // 2^0  (byte 0)
        0x100,              // 2^8  (byte 1)
        0x10000,            // 2^16 (byte 2)
        0x1000000,          // 2^24 (byte 3)
        0x100000000,        // 2^32 (byte 4)
        0x10000000000,      // 2^40 (byte 5)
        0x1000000000000,    // 2^48 (byte 6)
        0x100000000000000,  // 2^56 (byte 7)
    ];
    let idx: usize = byte_pos.into();
    *lookup.span()[idx]
}
