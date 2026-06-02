{
  description = "dl_file_share — relay WebSocket server";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll  = f: nixpkgs.lib.genAttrs systems
        (system: f system nixpkgs.legacyPackages.${system});
    in {
      packages = forAll (_system: pkgs: {
        default = pkgs.buildNpmPackage {
          pname   = "relay-server";
          version = "0.1.0";
          src     = ./.;

          npmDepsHash = "sha256-mHYpEL/eTTUGCpCypolTBq22zkkpHFLAbgHvyGcoax0=";

          dontBuild = true;

          installPhase = ''
            mkdir -p $out/lib/relay $out/bin
            cp relay-server.js $out/lib/relay/
            cp -r node_modules $out/lib/relay/

            makeWrapper ${pkgs.nodejs}/bin/node $out/bin/relay-server \
              --add-flags $out/lib/relay/relay-server.js \
              --chdir $out/lib/relay
          '';

          meta = {
            description = "WebSocket relay intermediário para o app dl_file_share";
            mainProgram = "relay-server";
          };
        };
      });

      apps = forAll (system: _pkgs: {
        default = {
          type    = "app";
          program = "${self.packages.${system}.default}/bin/relay-server";
        };
      });

      devShells = forAll (_system: pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.nodejs ];
        };
      });
    };
}
