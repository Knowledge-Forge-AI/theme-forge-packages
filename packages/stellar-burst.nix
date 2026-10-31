{ lib
, stdenv
, fetchurl
, nodejs_22
, makeWrapper
}:

let
  version = "0.7.0";
  pname = "theme-forge-stellar-burst";

  burstSrc = fetchurl {
    url = "https://github.com/Knowledge-Forge-AI/theme-forge-stellar-burst/releases/download/v0.7.0/knowledge-forge-ai-theme-forge-stellar-burst-0.7.0.tgz";
    sha256 = "c4b609a0b4705b17483577d5bde5deea518a83af08ce4d93c4662fa7cacc7d88";
  };

  depXmldom = fetchurl {
    url = "https://registry.npmjs.org/@xmldom/xmldom/-/xmldom-0.9.12.tgz";
    sha256 = "08245e18c248b957b4c6e07f8549ad5f55ae11b7a8abd4c1113a0fd61ddc67ee";
  };

  depFflate = fetchurl {
    url = "https://registry.npmjs.org/fflate/-/fflate-0.8.3.tgz";
    sha256 = "38c2cd824402407b43153c782274aec2ea83ea688e4aa0b743c5f2c305857d92";
  };

  depSmolToml = fetchurl {
    url = "https://registry.npmjs.org/smol-toml/-/smol-toml-1.9.1.tgz";
    sha256 = "4ac8392f1918c22a4366be19047cf53aa42646077d4c711b2ef73263beefb172"; # Archive authenticated against current tagged-lockfile SHA512; build acceptance held.
  };
in
stdenv.mkDerivation {
  inherit pname version;

  src = burstSrc;

  nativeBuildInputs = [ makeWrapper ];
  buildInputs = [ nodejs_22 ];

  dontBuild = true;

  # Keep authenticated release payloads, including native addons, byte-identical.
  # The install phase creates fixed Node wrappers and vendors locked dependencies.
  dontFixup = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib/theme-forge-stellar-burst
    cp -r * $out/lib/theme-forge-stellar-burst/

    # Vendor lock-bound runtime dependencies offline
    mkdir -p $out/lib/theme-forge-stellar-burst/node_modules/@xmldom/xmldom
    tar -xzf ${depXmldom} --strip-components=1 -C $out/lib/theme-forge-stellar-burst/node_modules/@xmldom/xmldom

    mkdir -p $out/lib/theme-forge-stellar-burst/node_modules/fflate
    tar -xzf ${depFflate} --strip-components=1 -C $out/lib/theme-forge-stellar-burst/node_modules/fflate

    mkdir -p $out/lib/theme-forge-stellar-burst/node_modules/smol-toml
    tar -xzf ${depSmolToml} --strip-components=1 -C $out/lib/theme-forge-stellar-burst/node_modules/smol-toml

    # Create wrapped bin launchers preserving dist/ and native/ sibling relationship
    mkdir -p $out/bin
    makeWrapper ${nodejs_22}/bin/node $out/bin/tfsb \
      --add-flags "$out/lib/theme-forge-stellar-burst/dist/cli.js"

    makeWrapper ${nodejs_22}/bin/node $out/bin/tfsb-studio-service \
      --add-flags "$out/lib/theme-forge-stellar-burst/dist/service-protocol/server-cli.js"

    runHook postInstall
  '';

  meta = with lib; {
    description = "Theme Forge Stellar Burst design token compiler and validation engine";
    homepage = "https://github.com/Knowledge-Forge-AI/theme-forge-packages";
    license = licenses.agpl3Plus;
    maintainers = [ ];
    platforms = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
    mainProgram = "tfsb";
  };
}
