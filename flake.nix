{
  description = "Pg_ibc helps decoding IBC packets and more";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix.url = "github:numtide/treefmt-nix";
    union.url = "github:unionlabs/union?rev=886643e65d49b8f2c7e2c1da814217c3f22aee8b";

    # shopify has a fix to select a cargo-pgrs version, which is required because it must match the one we use
    nixpkgs-pgrx.url = "github:Shopify/nixpkgs";
  };
  outputs = inputs@{ self, nixpkgs, crane, flake-parts, rust-overlay, union, nixpkgs-pgrx, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.treefmt-nix.flakeModule
      ];
      flake = {
        lib = {
          buildPgIbcExtension = pkgs-pgrx: postgresql: (pkgs-pgrx.buildPgrxExtension.override {
            cargo-pgrx = pkgs-pgrx.cargo-pgrx_0_12_6;
          } {
            inherit postgresql;
            src = ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = {
                "create3-0.1.0" = "sha256-bNidM1F7uV/CMKGuBPvbn3Xe4oKkqEX+kZh7oomnwsA=";
             };
            };
            name = "pg_ibc_0_2";
            doCheck = false;
          });
        };
      };
      systems =
        [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      perSystem = { self', system, lib, config, ... }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          pkgs-pgrx = import nixpkgs-pgrx {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          rust = pkgs.rust-bin.stable."1.81.0".default.override {
            extensions = [ "rust-src" ];
          };

          craneLib = crane.lib.${system}.overrideToolchain rust;
        in
        {
          packages = rec {
            default = pg_pfm_16;
            pg_pfm_14 = self.lib.buildPgIbcExtension pkgs-pgrx pkgs.postgresql_14;
            pg_pfm_15 = self.lib.buildPgIbcExtension pkgs-pgrx pkgs.postgresql_15;
            pg_pfm_16 = self.lib.buildPgIbcExtension pkgs-pgrx pkgs.postgresql_16;
          };
          treefmt.config = {
            projectRootFile = "flake.nix";
            programs = {
              nixpkgs-fmt.enable = true;
              rustfmt.enable = true;
            };
          };
          devShells.default = craneLib.devShell {
            checks = self.checks.${system};
            inputsFrom = with pkgs; [
              postgresql_13
              postgresql_14
              postgresql_15
              postgresql_16
              postgresql_17
            ];
            packages = with pkgs; [
              cargo-pgrx
              postgresql
              libiconv
              bison
              flex
              perl
              pkg-config
            ];
            # PGRX_HOME needs an absolute path for `cargo pgrx init` to work, but must be empty when running `nix build`
            PGRX_HOME="";
            # PGRX_HOME="/home/jurriaan/.pgrx";
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            PGRX_PG_SYS_SKIP_BINDING_REWRITE = "1";
            BINDGEN_EXTRA_CLANG_ARGS = [
              ''-I"${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.llvmPackages.libclang.version}/include"''
            ] ++ (if pkgs.stdenv.isLinux then [
              "-I ${pkgs.glibc.dev}/include"
            ] else [ ]);
          };
        };
    };
}
