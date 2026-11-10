# Original signing-runtime input relay

The qualified runtime-input Actions artifact from run 41549016980 is no longer available. Intake uses the fixed, non-latest evidence release `current-signer-runtime-inputs-41549016980-attempt-1` in this repository. The original ZIP is unchanged; it contains exactly 30 locked RPMs and the pinned quarantine manifest.

The runtime ZIP, complete corresponding-source ZIP and redistribution notices form one retained release set. All 18 exact source RPM signatures and signed payloads were verified, complete inventories checked, and all 23 supplemental pip notice bodies joined directly to the signed source tarball. Existing upstream-labelled Git pin metadata is retained without relying on tag resolution. Independent review cleared the redistribution inputs before upload.

Intake compiles the observed release/asset IDs, exact names, sizes and SHA-256 digests into its authenticated leaf. It verifies the original successful run, the exact lightweight tag target and all three asset identities before and after downloading the original ZIP. Missing, extra or changed assets fail closed. Mutable download counters and timestamps are excluded from that identity. The Actions route remains an explicit test seam and is never a production fallback.

Keep all three assets available together for as long as the binary ZIP is distributed. Removing a companion requires withdrawing the binary ZIP too. Loss of the relay or original run record is an availability failure, not permission to rebuild, repack or relax pins.

This transport change does not change signing identity, secret/environment scope, isolation or publication gates. Source tests and redistribution clearance do not establish native signer acceptance. Fresh paired RS9 admission, protected signing/client checks and same-source three-host GUI qualification remain required before the attended production deployment.
