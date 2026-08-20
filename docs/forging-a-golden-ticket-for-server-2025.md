# Forging a golden ticket that a fully-patched Windows Server 2025 KDC accepts — from scratch in Rust

*How the modern PAC hardening (KB5020805) actually works, why most from-scratch forgers fail against
2025, and what defenders should take from it. Authorized-lab research only.*

Conventional wisdom says golden tickets are a "solved" problem on patched domain controllers. They
aren't — a *correctly* forged ticket is still accepted by a fully-patched **Windows Server 2025**
KDC. What changed is the bar: the ticket's PAC now has to satisfy validation that older forgers
(and a lot of copy-pasted PAC code) simply don't produce. This post walks the exact structure that
makes a 2025 KDC say yes, implemented from scratch in pure Rust in
[ADhammer](https://github.com/icedracon/adhammer) — and ends with the defensive read.

## What a golden ticket actually is

A golden ticket is a **forged TGT**. Kerberos encrypts (seals) every TGT under the `krbtgt`
account's key; anyone who holds that key can mint a TGT for any identity, and the KDC will decrypt
and trust it. Inside the ticket is the **PAC** (Privilege Attribute Certificate) — the blob that
tells every downstream service *who you are and which groups you're in*. Forge a PAC that says
"Administrator, Domain Admins," seal it under the krbtgt key, and you are Domain Admin.

The krbtgt key comes from DCSync (`supplementalCredentials` → the krbtgt AES256 key). That part is
unchanged. The interesting part in 2025 is the PAC.

## Why naïve forgers fail on 2025 (KB5020805)

Two PAC buffers became mandatory as the November 2021 → 2022 patches (KB5008380 / KB5020805) moved
from "compatibility" to **enforcement**:

- **`PAC_ATTRIBUTES` (type 17)** — a small flags buffer.
- **`PAC_REQUESTOR` (type 18)** — the SID of the principal that requested the ticket.

A patched KDC cross-checks `PAC_REQUESTOR` against the account it's issuing for. A PAC that omits
these buffers — which is what a lot of older/hand-rolled forgers emit — is rejected outright. So
"my golden ticket used to work and now it doesn't" is usually *not* krbtgt rotation; it's the PAC
missing these buffers or getting their SID wrong.

## The PAC that works, buffer by buffer

The PAC is a `PACTYPE` container: a count, then an array of `(type, size, offset)` descriptors,
then each buffer 8-byte aligned. The buffers that matter:

```
PACTYPE
├─ LOGON_INFO      (1)  KERB_VALIDATION_INFO  — identity, RID, group RIDs, times
├─ CLIENT_INFO     (10) client name + auth time
├─ PAC_ATTRIBUTES  (17) flags
├─ PAC_REQUESTOR   (18) the requestor's SID  ← KB5020805
├─ SERVER_CHECKSUM (6)  signature over the PAC with the *server* (service) key
└─ KDC_CHECKSUM    (7)  signature over the SERVER_CHECKSUM with the *krbtgt* key
```

- **`KERB_VALIDATION_INFO`** is the big one. It's marshaled with MS-RPC **NDR
  Type-Serialization-v1** (not plain struct packing) — conformant pointers, referent IDs, 4/8-byte
  alignment, `RPC_UNICODE_STRING` payloads. Getting the referent ordering and the trailing
  `ExtraSids`/`ResourceGroups` pointers right is most of the work.
- **The two signatures** on a modern AES domain are **HMAC-SHA1-96 with the AES256 key
  (checksum type 16)**, not the old RC4 `KERB_CHECKSUM_HMAC_MD5`. The SERVER_CHECKSUM signs the PAC
  (with its own signature field zeroed); the KDC_CHECKSUM signs *that signature*. Order matters:
  zero both, compute SERVER, then compute KDC over the SERVER bytes.
- **`PAC_REQUESTOR`** is just the requestor SID in NDR — but it has to be the SID of the account the
  ticket claims to be, or the KDC refuses it.

Then the whole PAC goes into an `EncTicketPart`, sealed under the krbtgt AES256 key (key usage 2),
wrapped in an `AS-REP`-shaped ticket. Present it in a TGS-REQ and a patched 2025 KDC issues a
service ticket — the proof the forge is byte-correct.

## The result

Against a fully-patched Server 2025 DC in the lab, a forged Domain-Admin TGT is accepted: the KDC
decrypts it, validates the PAC (including the requestor check), and issues the service ticket. From
there, a Kerberos AP-REQ over SMB lands code execution as `NT AUTHORITY\SYSTEM` — the whole
`DCSync → forge → pass-the-ticket → SYSTEM` chain, run from Kali against the patched DC.

One honest nuance worth knowing: an **RC4** golden TGT is still *accepted* by 2025 (the KDC decrypts
it and validates the PAC), but the follow-on RC4 **service ticket** is refused with
`KDC_ERR_ETYPE_NOSUPP` — 2025 won't issue RC4 service tickets by policy. So on 2025 the working path
is AES end-to-end; RC4 golden completes only on an RC4-enabled DC (≤2022). That asymmetry surprised
me and is easy to misread as a forge bug when it's KDC policy.

## What defenders should take from this

- **Golden tickets are not mitigated — they're gated.** The PAC hardening raises the bar for the
  forger; it doesn't stop someone who holds the krbtgt key. The real control is protecting and
  rotating that key.
- **Rotate krbtgt twice** (with replication between), not once — a single reset leaves the previous
  key valid.
- **Detection still works on the artifacts**: TGTs with anomalous lifetimes, mismatched
  encryption types, or a client that never did an AS-REQ; TGS requests for a user with no preceding
  logon. PAC enforcement is a defense-in-depth layer *on top of* this, not a replacement.
- **Disabling RC4** genuinely helps: on the 2025 DC, RC4 service tickets are refused outright, which
  breaks a whole class of downgrade/silver-ticket tradecraft.

## Why build it from scratch

Everything above is implemented in Rust from scratch — a hand-rolled PAC marshaler, AES-checksum
signing, and Kerberos exchange — as part of an
[open-source AD security-assessment tool](https://github.com/icedracon/adhammer) that both *finds*
the paths and *proves* them with a live PoC per finding. Reimplementing the PAC from the MS-PAC
spec is how you actually learn where the enforcement lives — and it produced a reusable Rust
Kerberos/PAC layer that didn't exist before.

*Lab-only, authorized research. Built at ITMO. Tooling:
[github.com/icedracon/adhammer](https://github.com/icedracon/adhammer).*
