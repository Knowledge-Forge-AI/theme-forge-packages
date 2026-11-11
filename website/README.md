# Project website and package retention

This website is independent of product releases. Its builder uses only Python's
standard library. It never imports, installs, executes, rebuilds or re-signs a
downloaded package and has no signing environment or signing-secret mappings.

The assembly job accepts only the known initial hosting state or an immediately
previous successful run of this website workflow on main. Unknown publishers,
failed deployments and changed public input bytes stop assembly before any Pages
deployment. Partial public-only output is left for disposable-runner teardown.

The Packages site retains the exact 75 already-published files under apt/, arch/,
rpm/ and keys/. The committed inventory is pinned by its byte digest; every body
is fetched over verified HTTPS, size/hash checked, rechecked after adding the
five presentation assets and a separate website receipt, then checked again on the exact archived bodies. The closed archive is reopened
and its exact member set and protected digests are verified. Ownership and
timestamps are neutral. This adds six root files; none collides with
the qualified package inventory. Website assets are not claimed to be signed
package artifacts. The existing publication receipt continues to describe the
unchanged original package files.

The Packages workflow shares the existing current-package-publication concurrency
group, so it cannot race the maintained production publisher. A future package
publication changes repository metadata or the last publisher and therefore
requires a freshly reviewed protected inventory before another website refresh.

RS9's initial project-site route requires no recorded github-pages deployment
and an authenticated HTTPS 404 at the root. It currently has no Pages-publishing
workflow or recorded Pages deployment; package delivery lives on the separate
Theme Forge Packages origin. Subsequent refreshes accept only this website
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
Packages repository. The two helper copies must remain byte-identical; this is
checked during source review rather than enforced by a new runner.

Concurrency protects the running publisher. GitHub can replace an older pending
run in the same group with a newer one; do not start a website deployment while
an attended package publication is pending. A failed deployment refuses later
assembly. Rerun the failed deploy job while its one-day artifact remains; after
expiry, inspect the actual hosting state and prepare an explicit recovery rather
than bypassing the previous-publisher guard.

The committed inventory digest hashes the exact published PUBLIC-INVENTORY.json
file. PUBLICATION.json records the original inventory representation's digest;
it is not asserted to be the digest of that JSON map. This website pins the exact
published map and independently checks all 75 sizes and bodies against it.
