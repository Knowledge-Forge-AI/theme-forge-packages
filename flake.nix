{
  description = "Official public Nix packages for Theme Forge product family (Stellar Burst, Stellar Loom, Solar Sail, Nebular Fusion)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          burst = pkgs.callPackage ./packages/stellar-burst.nix { };
          loom = pkgs.callPackage ./packages/stellar-loom.nix { };
          sail = pkgs.callPackage ./packages/solar-sail.nix { };
          nebular = pkgs.callPackage ./packages/nebular-fusion.nix { };
        in
        {
          theme-forge-stellar-burst = burst;
          tfsb = burst;

          theme-forge-stellar-loom = loom;
          tfsl = loom;

          theme-forge-solar-sail = sail;
          tfss = sail;

          theme-forge-nebular-fusion = nebular;
          theme-forge-nebular-fusion-payload = nebular.payload;
          tfnf = nebular;

          default = if system == "aarch64-darwin" then nebular else burst;
        });

      apps = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          pkgsForSys = self.packages.${system};
        in
        nixpkgs.lib.filterAttrs (n: v: v != null) {
          tfsb = if pkgsForSys ? tfsb then {
            type = "app";
            program = "${pkgsForSys.tfsb}/bin/tfsb";
          } else null;

          tfsb-studio-service = if pkgsForSys ? tfsb then {
            type = "app";
            program = "${pkgsForSys.tfsb}/bin/tfsb-studio-service";
          } else null;

          tfsl = if pkgsForSys ? tfsl then {
            type = "app";
            program = "${pkgsForSys.tfsl}/bin/tfsl";
          } else null;

          tfsl-batch = if pkgsForSys ? tfsl then {
            type = "app";
            program = "${pkgsForSys.tfsl}/bin/tfsl-batch";
          } else null;

          tfss = if pkgsForSys ? tfss then {
            type = "app";
            program = "${pkgsForSys.tfss}/bin/tfss";
          } else null;

          tfnf = if pkgsForSys ? tfnf then {
            type = "app";
            program = "${pkgsForSys.tfnf}/bin/tfnf";
          } else null;

          default = if pkgsForSys ? tfnf then {
            type = "app";
            program = "${pkgsForSys.tfnf}/bin/tfnf";
          } else if pkgsForSys ? tfsb then {
            type = "app";
            program = "${pkgsForSys.tfsb}/bin/tfsb";
          } else null;
        });

      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          pkgsForSys = self.packages.${system};
        in
        nixpkgs.lib.filterAttrs (n: v: v != null) {
          cli-version-checks = if pkgsForSys ? tfsb && pkgsForSys ? tfsl && pkgsForSys ? tfss then
            pkgs.runCommand "cli-version-checks" { } ''
              ${pkgsForSys.tfsb}/bin/tfsb --version > burst-ver.txt
              grep -q "0.6.1" burst-ver.txt

              ${pkgsForSys.tfsl}/bin/tfsl --version > loom-ver.txt
              grep -q "0.4.0" loom-ver.txt

              ${pkgsForSys.tfss}/bin/tfss --version > sail-ver.txt
              grep -q "0.2.1" sail-ver.txt

              touch $out
            ''
          else null;

          nebular-check = if pkgsForSys ? tfnf then
            pkgs.runCommand "nebular-check" { } ''
              ${pkgsForSys.tfnf}/bin/tfnf --version > nebular-ver.txt
              grep -q "0.6.1" nebular-ver.txt
              touch $out
            ''
          else null;
        });
    };
}
