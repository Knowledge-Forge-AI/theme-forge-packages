{ lib
, stdenv
, fetchurl
, nodejs_22
, makeWrapper
}:

let
  version = "0.4.0";
  pname = "theme-forge-stellar-loom";

  loomSrc = fetchurl {
    url = "https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-stellar-loom/-/theme-forge-stellar-loom-${version}.tgz";
    sha256 = "4550314d9a6eb9a016c8637eb2a0a98e9a410210ad6546642dfce31c7402c9ec";
  };
in
stdenv.mkDerivation {
  inherit pname version;

  src = loomSrc;

  nativeBuildInputs = [ makeWrapper ];
  buildInputs = [ nodejs_22 ];

  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib/theme-forge-stellar-loom
    cp -r * $out/lib/theme-forge-stellar-loom/

    mkdir -p $out/bin
    makeWrapper ${nodejs_22}/bin/node $out/bin/tfsl \
      --add-flags "$out/lib/theme-forge-stellar-loom/bin/tfsl.js"

    makeWrapper ${nodejs_22}/bin/node $out/bin/tfsl-batch \
      --add-flags "$out/lib/theme-forge-stellar-loom/bin/tfsl-batch.js"

    runHook postInstall
  '';

  meta = with lib; {
    description = "Theme Forge Stellar Loom theme compiler and framework adapter";
    homepage = "https://github.com/Knowledge-Forge-AI/theme-forge-packages";
    license = licenses.agpl3Plus;
    maintainers = [ ];
    platforms = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
    mainProgram = "tfsl";
  };
}
