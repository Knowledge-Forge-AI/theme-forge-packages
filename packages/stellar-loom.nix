{ lib
, stdenv
, fetchurl
, nodejs_22
, makeWrapper
}:

let
  version = "0.5.0";
  pname = "theme-forge-stellar-loom";

  loomSrc = fetchurl {
    url = "https://github.com/Knowledge-Forge-AI/theme-forge-stellar-loom/releases/download/v0.5.0/knowledge-forge-ai-theme-forge-stellar-loom-0.5.0.tgz";
    sha256 = "4e7a7d436c09ba111f5dca8101876c6e085ad15859d96bab8f728c5669880b5f";
  };
in
stdenv.mkDerivation {
  inherit pname version;

  src = loomSrc;

  nativeBuildInputs = [ makeWrapper ];
  buildInputs = [ nodejs_22 ];

  dontBuild = true;
  # Fixed Node wrappers select the interpreter; preserve authenticated upstream JS bytes.
  dontPatchShebangs = true;

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
