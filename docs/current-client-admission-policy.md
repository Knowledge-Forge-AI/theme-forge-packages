# Current client admission preparation

Status: prepared source requiring fresh coordinated native qualification.
Source adoption and campaign execution require a separate operator decision;
this policy document does not authorize either operation or publication.

At source `d8122cf64bee331d63c6307432e97b024ec49c3e`, original qualification run
`42126045888` completed its full signer job successfully. Its retained artifact
passed the maintained archive validator, including the source-bound receipt,
native cryptographic-verification and cleanup flags, and the exact 75-file
public inventory. The ARM64 APT client passed. The other five clients refused
`QUALIFICATION_RUN_MISMATCH` during initial scheduling, before package-client
execution. The run failed and does not qualify production publication.

The original API responses were not retained. A transient aggregate status is
consistent with the timing but remains an inferred cause. Deterministic tests
establish the old predicate's refusal of otherwise identical `queued` metadata;
they do not establish the original hosted status or a unique native cause.

## Proposed intake rule

The client-only admission accepts aggregate `queued` or `in_progress` status
with an explicitly present, null conclusion. It continues to require the exact
workflow, repository, source, main branch, first attempt, completed successful
upstream signer, and active caller lane. The existing caller-lane predicate
remains unchanged: its states are `queued` or `in_progress`, and a non-null
conclusion is refused, retaining the previous treatment of a missing lane
conclusion field. Completed runs, non-null or
missing conclusions, waiting/pending/requested states and unknown statuses
remain refused. No retry, sleep or additional API request is introduced.

This does not bypass environment review: successful upstream signing remains
required, and only the signer job references the protected environment and its
secrets. Native client jobs retain their existing read-only permissions and
receive no signing credentials.

## Proposed fixed diagnostics

Run identity failures retain `QUALIFICATION_RUN_MISMATCH`. Aggregate state
failures produce one of eight fixed codes: `QUALIFICATION_RUN_STATUS_COMPLETED`,
`QUALIFICATION_RUN_STATUS_WAITING`, `QUALIFICATION_RUN_STATUS_PENDING`,
`QUALIFICATION_RUN_STATUS_REQUESTED`, `QUALIFICATION_RUN_STATUS_ACTION_REQUIRED`,
`QUALIFICATION_RUN_STATUS_OTHER`, `QUALIFICATION_RUN_CONCLUSION_ABSENT` or
`QUALIFICATION_RUN_CONCLUSION_NON_NULL`. Unknown strings, malformed values and
missing statuses map to `OTHER`; provider values and API bodies are not logged.
These labels can reveal coarse run-state and metadata-validity correlations.

The artifact snapshot, source rechecks, successful-signer and caller-lane gates,
archive inventory, package signatures, isolation and cleanup are preserved.
Final publication still requires an original completed successful qualification
run with all seven jobs, plus the separate same-source native GUI campaign.
The completed-run publication admission implementation is unchanged.

## Qualification and rollback

Pure regressions exercise both allowed aggregate states across all six lanes,
each identity field, unsuccessful or missing signer, inactive or foreign caller,
unknown state values, conclusions, and the unchanged final seven-job gate.
They execute no network, GPG, package managers or containers.

After owner adoption, a fresh original RS9 campaign must qualify the new paired
source pins. The final descriptor is then refreshed from that admitted original
run before one signing/client campaign and one same-source three-host GUI
campaign. A green campaign qualifies that candidate; it does not prove the
unique cause of the previous refusal. A failed or unexplained result
stops successors. Production deployment is separately controlled.

Rollback restores the previous source and paired hash pins as one coordinated
change. Do not mix new client code with the old authenticated leaf manifest,
bootstrap, workflow or RS9 consumer pins. Existing signing identity, secrets,
environment protections, dependency versions and lockfiles remain unchanged.
