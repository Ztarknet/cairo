# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Important Notes

- **Do not read** `crates/cairo-lang-syntax/src/node/ast.rs`. Instead read `crates/cairo-lang-syntax-codegen/src/generator.rs` - the AST is auto-generated from this file.
- When finishing a feature, run `./scripts/rust_fmt.sh` and `./scripts/clippy.sh`.

## Build and Development Commands

```bash
# Run all tests
cargo test

# Run a single test
cargo test <test_name>

# Run tests with filtering
CAIRO_TEST_FILTER=foo cargo test

# Fix test expectations automatically
CAIRO_FIX_TESTS=1 cargo test

# Skip format checks during tests
CAIRO_SKIP_FORMAT_TESTS=1 cargo test

# Format Rust code (uses nightly toolchain)
./scripts/rust_fmt.sh

# Run clippy lints
./scripts/clippy.sh

# Regenerate syntax AST files
cargo run --bin generate-syntax
```

## Key Binaries

- `cairo-compile` - Compile Cairo to Sierra
- `sierra-compile` - Compile Sierra to CASM (Cairo assembly)
- `cairo-run` - Run Cairo code directly
- `cairo-test` - Run Cairo tests
- `starknet-compile` - Compile Starknet contracts to Sierra ContractClass
- `starknet-sierra-compile` - Compile ContractClass to CompiledClass

## Architecture Overview

This is the Cairo compiler, written in Rust. The compilation pipeline is:

**Cairo Source → Sierra → CASM (Cairo Assembly)**

### Core Crates

- `cairo-lang-syntax` / `cairo-lang-syntax-codegen` - Syntax tree and AST (AST is auto-generated)
- `cairo-lang-parser` - Parses Cairo source into AST
- `cairo-lang-semantic` - Semantic analysis and type checking
- `cairo-lang-lowering` - Lowers semantic representation to FlatLowered
- `cairo-lang-sierra-generator` - Generates Sierra from lowered representation
- `cairo-lang-sierra` - Sierra IR data structures
- `cairo-lang-sierra-to-casm` - Compiles Sierra to CASM
- `cairo-lang-casm` - CASM data structures

### Starknet-Specific

- `cairo-lang-starknet` - Starknet contract compilation
- `cairo-lang-starknet-classes` - ContractClass definitions

### Supporting Crates

- `cairo-lang-defs` - Definitions and items
- `cairo-lang-diagnostics` - Compiler diagnostics/errors
- `cairo-lang-plugins` - Compiler plugins (derives, attributes)
- `cairo-lang-formatter` - Cairo code formatter
- `cairo-lang-runner` - Execute compiled Cairo

### Corelib

The `corelib/` directory contains the Cairo standard library.

## Rust Toolchain

- Requires Rust 1.86+
- Uses nightly-2025-11-17 for formatting and clippy
