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

          # Package evidence only: never enter bubblewrap or Tauri in a build sandbox.
          nebular-package-check = if pkgsForSys ? tfnf then
            let
              tfnf = pkgsForSys.tfnf;
              contract = (builtins.fromJSON (builtins.readFile ./release-lock.json)).products.theme-forge-nebular-fusion;
              archive = contract.rawArchives.${system};
              darwin = pkgs.stdenv.hostPlatform.isDarwin;
              source = if darwin then tfnf.src else tfnf.payload.src;
              installed = if darwin then "${tfnf}/Applications/Theme Forge Nebular Fusion.app"
                else "${tfnf.payload}/lib/theme-forge-nebular-fusion";
              archiveRoot = if darwin then "Theme Forge Nebular Fusion.app" else "theme-forge-nebular-fusion";
              launcher = if darwin then "${installed}/Contents/Resources/bin/tfnf" else "${installed}/bin/tfnf";
              gui = if darwin then "${installed}/Contents/MacOS/theme-forge-nebular-fusion"
                else "${installed}/bin/theme-forge-nebular-fusion";
            in pkgs.runCommand "nebular-package-check" {
              nativeBuildInputs = [ pkgs.coreutils pkgs.diffutils pkgs.findutils ]
                ++ pkgs.lib.optionals (!darwin) [ pkgs.binutils ];
            } ''
              mkdir original
              tar -xzf ${source} -C original
              diff -r --no-dereference "original/${archiveRoot}" "${installed}"
              test "$(sha256sum "${gui}" | cut -d ' ' -f 1)" = "${archive.executableSha256}"
              test -x "${launcher}"
              test -x "${gui}"
              test ! -L "${gui}"
              # Nix normalizes write bits; every archived executable must remain executable.
              (cd "original/${archiveRoot}" && find . -type f -perm /111 -printf '%P\0') > archived-executables
              test -s archived-executables
              while IFS= read -r -d $'\0' member; do
                test -x "${installed}/$member"
              done < archived-executables
              ${pkgs.lib.optionalString darwin ''
                test "$(readlink ${tfnf}/bin/tfnf)" = "${launcher}"
              ''}
              # Execute the released shell launcher directly, bypassing the Linux FHS wrapper.
              test "$(${pkgs.runtimeShell} "${launcher}" --version)" = "theme-forge-nebular-fusion ${contract.version}"
              test "$(${pkgs.runtimeShell} "${launcher}" --path)" = "$(realpath "${gui}")"
              ${pkgs.lib.optionalString (!darwin) ''
                test -x ${tfnf}/bin/tfnf
                grep -qxF ${tfnf.payload} ${pkgs.closureInfo { rootPaths = [ tfnf ]; }}/store-paths
                # Checked producers, mandatory ELFs and exact root-relative PT_INTERP.
                ${pkgs.runtimeShell} ${./tools/verification/check-nebular-fhs-closure.sh} \
                  --installed "${installed}" --fhs-root "${tfnf.fhsenv}" \
                  --require "${gui}" --require "${installed}/bin/tfsb-studio-service"
              ''}
              touch $out
            ''
          else null;
        });
    };
}
