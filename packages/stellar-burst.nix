{ lib
, stdenv
, fetchurl
, nodejs_22
, makeWrapper
}:

let
  version = "0.6.1";
  pname = "theme-forge-stellar-burst";

  burstSrc = fetchurl {
    url = "https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-stellar-burst/-/theme-forge-stellar-burst-${version}.tgz";
    sha256 = "53ef41a3de3335e042f2c4b1d299b1155b64bfc6556a84baf6a62cb28bcca209";
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
    url = "https://registry.npmjs.org/smol-toml/-/smol-toml-1.8.0.tgz";
    sha256 = "1fc995be91cdb777fc13e20c2edfebaaf60ef4e4d2d5331caef2837b04d37892";
  };
in
stdenv.mkDerivation {
  inherit pname version;

  src = burstSrc;

  nativeBuildInputs = [ makeWrapper ];
  buildInputs = [ nodejs_22 ];

  dontBuild = true;

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
