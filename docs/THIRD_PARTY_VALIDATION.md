# Third-party validation

Independent reproduction is one of the strongest signals ADhammer can collect. This guide explains how external researchers, operators, and defenders can validate documented behavior without exposing sensitive engagement data.

## What counts as useful validation

Useful validation is reproducible, versioned, authorized, and specific enough to review. It should identify:

- ADhammer release or commit;
- the exact capability from `docs/VALIDATION.md`;
- the sanitized environment characteristics that materially affect behavior;
- whether the result succeeded, failed closed, or differed from the ledger;
- evidence sufficient for a maintainer to understand the result.

A screenshot alone is weak evidence. A sanitized command transcript, packet observation, test fixture, result hash, or structured receipt is stronger.

## Safety and privacy

Do not submit:

- real credentials or password material;
- private keys or ticket material;
- customer or employer names unless they explicitly approved disclosure;
- real user names, host names, SIDs, internal DNS names, or routable/private infrastructure inventories;
- unsanitized packet captures from production systems.

Prefer placeholders such as `corp.local`, `DC01`, `10.0.0.10`, and redacted SIDs. Validate only systems you own or are explicitly authorized to test.

## Recommended workflow

1. Read `docs/VALIDATION.md` and select one capability.
2. Record the ADhammer version or commit SHA.
3. Reproduce the behavior in an authorized lab or approved assessment environment.
4. Sanitize all evidence before sharing it.
5. Compare the observed result with the ledger status.
6. Open a **Validation report** issue using the repository template.

## Environment metadata

Include only metadata relevant to the result, for example:

- Windows Server 2019 / 2022 / 2025;
- domain functional level if it materially changes behavior;
- AD CS present / absent and CA role where relevant;
- patched or intentionally vulnerable lab state where relevant;
- feature flags or non-default build settings.

Do not include identifying infrastructure details.

## Result categories

### Reproduced

The documented behavior matches the current release and evidence supports the same interpretation as the ledger.

### Negative validation

The capability correctly fails closed or reports the expected negative condition in an environment where success should not occur. Negative results are valuable when they verify safety boundaries or version-specific behavior.

### Divergence

The observed behavior differs from the ledger, documentation, or expected protocol behavior. Open a validation report and describe the divergence precisely. If the divergence reveals a vulnerability in ADhammer itself, use the private process in `SECURITY.md` instead.

## Evidence quality

Preferred evidence, roughly strongest first:

1. reproducible test or sanitized structured receipt;
2. sanitized protocol / packet-level observation;
3. deterministic CLI transcript with environment metadata;
4. cross-tool interoperability comparison;
5. screenshot with enough context to review.

Independent reproduction does not automatically change a ledger row. Maintainers should review the evidence, reproduce when practical, and update `docs/VALIDATION.md` in a separate traceable change.

## Credit

External validators should be credited in the issue, release notes, or validation documentation when they want attribution. Anonymous validation is also acceptable when the evidence is sufficient to review.
