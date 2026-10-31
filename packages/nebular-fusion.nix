{ lib
, stdenv
, fetchurl
, makeWrapper
, buildFHSEnv ? null
, gtk3
, gdk-pixbuf
, glib
, webkitgtk_4_1
, libsoup_3
, cairo
, pango
, openssl
, zlib
, dbus
}:

let
  version = "0.7.1";
  pname = "theme-forge-nebular-fusion";
  system = stdenv.hostPlatform.system;

  sources = {
    "aarch64-darwin" = {
      url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v${version}/theme-forge-nebular-fusion-v${version}-aarch64-apple-darwin.app.tar.gz";
      sha256 = "903d7380dd54c9070e944be22c08137141d24a6e3c3f5a1f8fb53c61e9a2b342";
    };
    "aarch64-linux" = {
      url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v${version}/theme-forge-nebular-fusion-v${version}-aarch64-unknown-linux-gnu.tar.gz";
      sha256 = "8341d0069dd729d4d7e535b42d411edb8fee02c402fbcf0c861514a64f09c608";
    };
    "x86_64-linux" = {
      url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v${version}/theme-forge-nebular-fusion-v${version}-x86_64-unknown-linux-gnu.tar.gz";
      sha256 = "3a0f9fc991c94588ec06bbe9e0dc4a40250e11f8d238bd8a11cad9ce6fc98c5c";
    };
  };

  selectedSource = sources.${system} or (throw "Unsupported system for Nebular Fusion: ${system}");

  rawArchive = fetchurl {
    inherit (selectedSource) url sha256;
  };

  isDarwin = stdenv.hostPlatform.isDarwin;

  darwinPackage = stdenv.mkDerivation {
    inherit pname version;
    src = rawArchive;
    sourceRoot = ".";
    nativeBuildInputs = [ makeWrapper ];

    dontStrip = true;
    dontPatchELF = true;
    # Preserve the authenticated archive, including the sealed Darwin launcher.
    dontFixup = true;

    installPhase = ''
      runHook preInstall
      mkdir -p "$out/Applications"
      cp -r "Theme Forge Nebular Fusion.app" "$out/Applications/"

      mkdir -p "$out/bin"
      ln -s "$out/Applications/Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf" "$out/bin/tfnf"
      runHook postInstall
    '';

    passthru = {
      payload = darwinPackage;
    };

    meta = with lib; {
      description = "Theme Forge Nebular Fusion design system studio and theme compiler workbench";
      homepage = "https://github.com/Knowledge-Forge-AI/theme-forge-packages";
      license = licenses.agpl3Plus;
      maintainers = [ ];
      platforms = [ "aarch64-darwin" ];
      mainProgram = "tfnf";
    };
  };

  linuxPayload = stdenv.mkDerivation {
    pname = "${pname}-payload";
    inherit version;
    src = rawArchive;
    sourceRoot = ".";

    dontStrip = true;
    dontPatchELF = true;
    # The FHS environment supplies dependencies without rewriting release bytes.
    dontFixup = true;

    installPhase = ''
      runHook preInstall
      mkdir -p "$out/lib/theme-forge-nebular-fusion"
      cp -r theme-forge-nebular-fusion/* "$out/lib/theme-forge-nebular-fusion/"
      runHook postInstall
    '';
  };

  linuxFhsPackage = if buildFHSEnv != null then
    buildFHSEnv {
      name = "tfnf";
      targetPkgs = pkgs: [
        gtk3
        gdk-pixbuf
        glib
        webkitgtk_4_1
        libsoup_3
        cairo
        pango
        openssl
        zlib
        dbus
      ];
      runScript = "${linuxPayload}/lib/theme-forge-nebular-fusion/bin/tfnf";

      extraInstallCommands = ''
        mkdir -p "$out/share/applications"
      '';

      passthru = {
        payload = linuxPayload;
      };

      meta = with lib; {
        description = "Theme Forge Nebular Fusion design system studio and theme compiler workbench";
        homepage = "https://github.com/Knowledge-Forge-AI/theme-forge-packages";
        license = licenses.agpl3Plus;
        maintainers = [ ];
        platforms = [ "x86_64-linux" "aarch64-linux" ];
        mainProgram = "tfnf";
      };
    }
  else
    stdenv.mkDerivation {
      inherit pname version;
      src = rawArchive;
      sourceRoot = ".";
      nativeBuildInputs = [ makeWrapper ];

      dontStrip = true;
      dontPatchELF = true;

      installPhase = ''
        runHook preInstall
        mkdir -p "$out/lib/theme-forge-nebular-fusion"
        cp -r theme-forge-nebular-fusion/* "$out/lib/theme-forge-nebular-fusion/"

        LIBPATH="${lib.makeLibraryPath [
          gtk3
          gdk-pixbuf
          glib
          webkitgtk_4_1
          libsoup_3
          cairo
          pango
          openssl
          zlib
          dbus
        ]}"

        mkdir -p "$out/bin"
        makeWrapper "$out/lib/theme-forge-nebular-fusion/bin/tfnf" "$out/bin/tfnf" \
          --prefix LD_LIBRARY_PATH : "$LIBPATH"
        runHook postInstall
      '';

      passthru = {
        payload = linuxPayload;
      };

      meta = with lib; {
        description = "Theme Forge Nebular Fusion design system studio and theme compiler workbench";
        homepage = "https://github.com/Knowledge-Forge-AI/theme-forge-packages";
        license = licenses.agpl3Plus;
        maintainers = [ ];
        platforms = [ "x86_64-linux" "aarch64-linux" ];
        mainProgram = "tfnf";
      };
    };
in
if isDarwin then darwinPackage else linuxFhsPackage
