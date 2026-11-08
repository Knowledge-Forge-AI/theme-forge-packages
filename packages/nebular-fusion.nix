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
  version = "0.8.0";
  pname = "theme-forge-nebular-fusion";
  system = stdenv.hostPlatform.system;

  sources = {
    "aarch64-darwin" = {
      url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v${version}/theme-forge-nebular-fusion-v${version}-aarch64-apple-darwin.app.tar.gz";
      sha256 = "0a7ab188afc4660f68bd6dabfda96309a348108a8d77a4786df1731cddaf6896";
    };
    "aarch64-linux" = {
      url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v${version}/theme-forge-nebular-fusion-v${version}-aarch64-unknown-linux-gnu.tar.gz";
      sha256 = "4bbc40f180d954e1ca496606da9b63d7ce0f49dd29e802893aabc4aa0e859e94";
    };
    "x86_64-linux" = {
      url = "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v${version}/theme-forge-nebular-fusion-v${version}-x86_64-unknown-linux-gnu.tar.gz";
      sha256 = "498f0f6ff81c32200843e04016f86f7733905df0b0712c3f3639162ad5655abc";
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
