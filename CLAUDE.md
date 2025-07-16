# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pg_ibc is a PostgreSQL extension for handling Inter-Blockchain Communication (IBC) packets. It provides functions for decoding and validating various IBC packet formats, supporting different blockchain protocols like EVM, Cosmos, Osmosis, and others.

The extension is built using Rust with the pgrx framework for PostgreSQL extension development.

## Development Environment

This project uses Nix for development environment management. The development shell provides all necessary tools for building, testing, and packaging the extension. The project uses the latest stable Rust toolchain provided by the rust-overlay.

### Setup and Building

1. Initialize the development environment:
   ```bash
   direnv allow  # If using direnv
   # OR
   nix develop
   ```

2. Initialize pgrx (first time only):
   ```bash
   cargo pgrx init
   ```

3. Building the extension:
   ```bash
   cargo pgrx build
   ```

4. Running tests:
   ```bash
   cargo pgrx test
   ```

5. Running a specific test:
   ```bash
   cargo test test_name -- --nocapture
   ```

6. Install the extension in a PostgreSQL instance:
   ```bash
   cargo pgrx install
   ```

### PostgreSQL versions

The extension supports multiple PostgreSQL versions (14, 15, 16) using feature flags:
- `pg14` (default)
- `pg15`
- `pg16`

To build for a specific PostgreSQL version:
```bash
cargo pgrx build --features pg15
```

## SQL Functions

The extension exposes several SQL functions for working with IBC packets:

1. `decode_transfer_packet_0_1(input, rpc_type, throws, extension_format)`: Decodes packet data from different blockchain RPC types.

2. `decode_ack_0_1(packet, ack, channel_version)`: Decodes acknowledgment data for specific channel versions.

3. `decode_packet_0_1(packet, channel_version)`: Decodes packet data for specific channel versions.

4. `decode_packet_ack_0_1/0_2/0_3`: Different versions of functions to decode packet and acknowledgment data together.

5. `predict_osmosis_wrapper_0_1`: Predicts Osmosis wrapper addresses based on channel IDs and token info.

## Architecture

The codebase is organized by blockchain/protocol types:

- `src/lib.rs`: Main entry point with core decoding functions
- `src/aptos/`: Aptos blockchain specific code
- `src/cosmos/`: Cosmos protocol specific code
- `src/create3/`: Implementation for CREATE3 contract deployment pattern
- `src/erc55/`: ERC-55 address checksum implementation
- `src/instantiate2/`: Implementation for INSTANTIATE2 contract deployment pattern
- `src/osmosis/`: Osmosis blockchain specific code
- `src/ucs03_zkgm_0/`: Implementation of UCS03-ZKGM-0 protocol
  - `ack.rs`: Acknowledgment handling
  - `packet.rs`: Packet handling
  - `packet_ack.rs`: Combined packet+ack handling

## Coding Guidelines

1. Format code using the repository's Rust formatting rules:
   ```bash
   cargo fmt
   ```

2. Run clippy for linting:
   ```bash
   cargo clippy
   ```

3. Before committing, ensure all tests pass:
   ```bash
   cargo pgrx test
   ```

## Current Development

The project is actively adding support for new blockchain protocols and packet formats. The recent features include:
- Osmosis wrapper prediction functionality
- Improvements to packet hash calculation