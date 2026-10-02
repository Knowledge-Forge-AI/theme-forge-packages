{ lib
, stdenv
, fetchurl
, nodejs_22
, makeWrapper
}:

let
  version = "0.2.1";
  pname = "theme-forge-solar-sail";

  sailSrc = fetchurl {
    url = "https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-solar-sail/-/theme-forge-solar-sail-${version}.tgz";
    sha256 = "ebc4f21d1e61dbc0ac4e87ce81f7ecec4f97d7c15562356e429d4c1a4e9aa5a0";
  };
in
stdenv.mkDerivation {
  inherit pname version;

  src = sailSrc;

  nativeBuildInputs = [ makeWrapper ];
  buildInputs = [ nodejs_22 ];

  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib/theme-forge-solar-sail
    cp -r * $out/lib/theme-forge-solar-sail/

    mkdir -p $out/bin
    makeWrapper ${nodejs_22}/bin/node $out/bin/tfss \
      --add-flags "$out/lib/theme-forge-solar-sail/bin/tfss.js"

    runHook postInstall
  '';

  meta = with lib; {
    description = "Theme Forge Solar Sail pairing engine and design token validator";
    homepage = "https://github.com/Knowledge-Forge-AI/theme-forge-packages";
    license = licenses.agpl3Plus;
    maintainers = [ ];
    platforms = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
    mainProgram = "tfss";
  };
}
