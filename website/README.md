# Project website and package retention

This website is independent of product releases. Its builder uses only Python's
standard library. It never imports, installs, executes, rebuilds or re-signs a
downloaded package and has no signing environment or signing-secret mappings.

The assembly job accepts the known initial hosting state, an immediately
previous successful run of this website workflow on main, or the exact failed
history described below. Unknown publishers, other failed deployments and
changed public input bytes stop assembly before any Pages
deployment. Partial public-only output is left for disposable-runner teardown.

The Packages site retains the exact 75 already-published files under apt/, arch/,
rpm/ and keys/. The committed inventory is pinned by its byte digest; every body
is fetched over verified HTTPS, size/hash checked, rechecked after adding the
seven presentation assets and a separate website receipt, then checked again on the exact archived bodies. The closed archive is reopened
and its exact member set and protected digests are verified. Ownership and
timestamps are neutral. This adds eight root files; none collides with
the qualified package inventory. Website assets are not claimed to be signed
package artifacts. The existing publication receipt continues to describe the
unchanged original package files.

The Packages workflow shares the existing current-package-publication concurrency
group, so it cannot race the maintained production publisher. A future package
publication changes repository metadata or the last publisher and therefore
requires a freshly reviewed protected inventory before another website refresh.

RS9's initial project-site route required no recorded github-pages deployment
and a certificate-verified HTTPS 404 at the root. Its project page is now live;
package delivery lives on the separate Theme Forge Packages origin. Subsequent
RS9 refreshes accept only its website
workflow. Before activating package hosting on the RS9 origin, retire this
project-only route or adopt an exact protected inventory and share its
rs9-pages-publication concurrency group. Do not deploy a website-only tree over
an origin that has acquired package-serving responsibilities.

Both routes retain the existing github-pages protection and exact main-branch
condition. RS9 environment readback confirms reviewer lair001, self-review
allowed, and a selected exact main branch rule; Pages uses GitHub Actions with
the verified rs9.knowledge-forge.ai domain and HTTPS enforcement. No release, dependency, key, registry or repository-protection change
is part of this workflow. Normal source CI still applies. The maintained assembly tests are local validation,
not an added hosted gate: run python3 -I -B website/test/test_assembly.py in the
Packages repository. The initial helper copies were identical. This repository
now has the nested archive correction and exact failed-deployment recovery
below; RS9's working flat project-site helper stays at its prior version.
Changes to either helper require their own source review; neither is an
installed shared dependency.

Concurrency protects the running publisher. GitHub can replace an older pending
run in the same group with a newer one; do not start a website deployment while
an attended package publication is pending. A failed deployment refuses later
assembly. Rerun the failed deploy job while its one-day artifact remains; after
expiry, inspect the actual hosting state and prepare an explicit recovery rather
than bypassing the previous-publisher guard. The exact inspected recovery below
does not grant acceptance to other failed histories.

The committed inventory digest hashes the exact published PUBLIC-INVENTORY.json
file. PUBLICATION.json records the original inventory representation's digest;
it is not asserted to be the digest of that JSON map. This website pins the exact
published map and independently checks all 75 sizes and bodies against it.

## Nested archive transport and inspected recovery

The first website deployment and its one same-artifact retry failed in Pages
with only a generic deployment error. All 75 public package bodies still match
the admitted inventory. The cause is unproved. The next controlled correction
uses the last working publisher's archive topology: explicit root and ancestor
directory entries, followed by regular files with `./`-rooted names. GNU long-name
headers match the working Ubuntu publisher's GNU tar encoding instead of USTAR
prefix/name splitting. Neither transport difference is a proven root cause. Directory
mode is 0755, file mode is 0644, and ownership/timestamps remain neutral. The
closed archive must have exactly those directories and files, no links, and all
original protected sizes/hashes. Extracted public paths and file bytes do not change.

Recovery accepts only failed deployments 7709348450 and 7704763715, in that
order, immediately above successful original deployment 7688464725. Both failed
entries must match the exact main source, job links and completed attempt 2 of
website run 42982720952; the original success retains its exact source/job pin.
Any inserted, missing, reordered, foreign, changed or ongoing entry refuses.
The public inventory is then fetched and checked in full, the closed archive is
verified, and the hosting admission is read back unchanged before upload.
Do not rerun 42982720952 or start another Pages deployment before this correction:
either changes the pinned history and stops this recovery. The final readback is
before the environment-review wait; the shared publisher mutex remains the
existing protection through deployment, rather than a new post-approval readback.

This is not a general failed-publisher exception or permission to retry unknown
failures. No signing, package publication, key, permission, protection, workflow
or dependency changes are included. Another failure requires diagnosis before
further deployment. A successful first hosted extraction and live 75-file
readback remain required; local tar checks do not prove the Pages root cause.

The website includes two mascot WebPs: original Orihime and established Hikari.
They are presentation assets, not signed packages, product releases, or changes
to the protected inventory.

The paired mascot section uses Orihime for Theme Forge and Hikari for RS9. The
new Hikari file is an exact copy of the established public illustration. Both
are presentation assets outside the protected package inventory; no package,
public key or repository metadata is changed by this addition.
