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

  };
  outputs = inputs@{ self, nixpkgs, crane, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.treefmt-nix.flakeModule
      ];
      flake = {
        lib = {
          buildPgIbcExtension = pkgs: postgresql: (pkgs.buildPgrxExtension {
            inherit postgresql;
            src = ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            name = "pg_ibc";
            doCheck = false;
          });
        };
      };
      systems =
        [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      perSystem = { self', system, lib, config, pkgs, ... }:
        let
          craneLib = crane.lib.${system};
        in
        {
          packages = rec {
            default = pg_pfm_16;
            pg_pfm_14 = self.lib.buildPgIbcExtension pkgs pkgs.postgresql_14;
            pg_pfm_15 = self.lib.buildPgIbcExtension pkgs pkgs.postgresql_15;
            pg_pfm_16 = self.lib.buildPgIbcExtension pkgs pkgs.postgresql_16;
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
              postgresql_12
              postgresql_13
              postgresql_14
              postgresql_15
              postgresql_16
            ];
            packages = with pkgs; [
              cargo-pgrx
              postgresql
              libiconv
              pkg-config
            ];
            PGRX_HOME = "";
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
