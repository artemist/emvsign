{
  description = "Sign arbitrary files with an EMV card";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      lib = nixpkgs.lib;
      makePkgs =
        system:
        import nixpkgs {
          inherit system;
        };
      forAllSystems = f: lib.genAttrs lib.systems.flakeExposed (system: f (makePkgs system));
    in
    {
      packages = forAllSystems (pkgs: rec {
        emvsign =
          with pkgs;
          rustPlatform.buildRustPackage rec {
            name = "emvsign";
            version = "0.1";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            doCheck = false;
            nativeBuildInputs = [ pkg-config ];
            buildInputs = [
              dbus
              pcsclite
            ];

            meta = with lib; {
              homepage = "https://github.com/artemist/emvsign";
              description = "Sign arbitraty files with an EMV card";
              maintainers = with maintainers; [ artemist ];
              license = with licenses; [ mit ];
              platforms = platforms.unix;
            };
          };
        default = emvsign;
      });

      shells = forAllSystems (pkgs: rec {
        emvsign =
          with pkgs;
          mkShell {
            packages = [
              pkg-config
              rustc
              cargo
              clippy
              pcsclite
            ];
            RUST_SRC_PATH = "${rust.packages.stable.rustPlatform.rustLibSrc}";
          };
        default = emvsign;
      });
    };
}
