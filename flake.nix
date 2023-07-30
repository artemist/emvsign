{
  description = "Sign arbitrary files with an EMV card";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
    in
    (utils.lib.eachSystem supportedSystems (system:
      let pkgs = import nixpkgs { inherit system; };
      in
      rec {
        packages.emvsign = with pkgs; rustPlatform.buildRustPackage rec {
          name = "emvsign";
          version = "0.1";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;
          nativeBuildInputs = [ pkgconfig ];
          buildInputs = [ dbus ];

          meta = with lib; {
            homepage = "https://github.com/artemist/emvsign";
            description = "Sign arbitraty files with an EMV card";
            maintainers = with maintainers; [ artemist ];
            license = with licenses; [ mit ];
            platforms = supportedSystems;
          };
        };
        defaultPackage = packages.emvsign;

        apps.emvsign = utils.lib.mkApp { drv = packages.emvsign; };
        defaultApp = apps.emvsign;

        overlay = final: prev: {
          inherit (packages) emvsign;
        };

        devShells.emvsign = with pkgs; mkShell {
          packages = [ pkgconfig rustc cargo clippy pcsclite ];
          RUST_SRC_PATH = "${rust.packages.stable.rustPlatform.rustLibSrc}";
        };
        devShell = devShells.emvsign;
      })) // {
      overlay = final: prev: {
        inherit (self.packages."${prev.system}") emvsign;
      };
    };
}
