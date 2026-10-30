{ lib
, stdenv
, fetchurl
, nodejs_22
, makeWrapper
}:

let
  version = "0.3.0";
  pname = "theme-forge-solar-sail";

  sailSrc = fetchurl {
    url = "https://github.com/Knowledge-Forge-AI/theme-forge-solar-sail/releases/download/v0.3.0/knowledge-forge-ai-theme-forge-solar-sail-0.3.0.tgz";
    sha256 = "65070c3478a1d55476c1b09fbe1dcadfdf7c3d3aa54a154bc9ac9e299411f415";
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
