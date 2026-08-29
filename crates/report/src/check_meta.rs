//! **1.4.6 WS-COVERAGE-META**: hypothetical-impact fallback for the coverage matrix.
//!
//! Every `adhammer_checks::registry()` check gets a short static description here — title,
//! hypothetical impact ("if this had tripped, X would happen"), remediation, and MITRE
//! ATT&CK mapping. Populated into `CheckCoverage` rows that are **clean** so an operator
//! can verify what the check was looking for and rule out check-code bugs before trusting
//! "no findings" as "not vulnerable".
//!
//! **1.4.7 WS-CTRLMAP**: every check also carries in-house AD-pentest taxonomy tags —
//! `control_areas` (one or more `ADP-NN` codes; see `docs/CONTROL_AREAS.md`) and
//! `kill_chain_phase` (one of `enumeration | initial-access | privilege-escalation |
//! lateral-movement | persistence | domain-dominance`). The coverage matrix + report
//! panels group by these so an operator can answer "which pentest control areas did
//! this assessment exercise, and what was the result per area?" without any third-party
//! methodology labels. A CI gate rejects any check that ships without at least one
//! control area and a non-empty phase (empty tags -> `cargo test` fails).
//!
//! Not the source of truth for tripped findings — those still emit their own richer
//! Finding.title / Finding.impact. This is the parallel copy for the clean case + the
//! machine-readable methodology roll-up.

pub struct CheckMeta {
    pub title: &'static str,
    pub hypothetical_impact: &'static str,
    pub remediation: &'static str,
    pub mitre: &'static [&'static str],
    /// One or more `ADP-NN` in-house AD-pentest control-area codes; see
    /// `docs/CONTROL_AREAS.md` for the numbering. Every populated check must list
    /// at least one (CI-gated).
    pub control_areas: &'static [&'static str],
    /// One of `enumeration | initial-access | privilege-escalation | lateral-movement |
    /// persistence | domain-dominance`. Generic kill-chain phase — no cert-body naming.
    pub kill_chain_phase: &'static str,
}

const UNKNOWN: CheckMeta = CheckMeta {
    title: "",
    hypothetical_impact: "",
    remediation: "",
    mitre: &[],
    control_areas: &[],
    kill_chain_phase: "",
};

/// Look up a check's title/hypothetical impact/remediation/MITRE + taxonomy tags by its
/// `Check::id()`. Returns `CheckMeta::UNKNOWN` (all-empty) if the id is not in this table
/// — safe default that renders as "no description available" rather than crashing.
pub fn describe(id: &str) -> CheckMeta {
    match id {
        // --- Privileged (P-*) ---
        "P-AsrepRoast" => CheckMeta {
            title: "Accounts do not require Kerberos pre-authentication",
            hypothetical_impact: "Attackers can request an AS-REP for the account and offline-crack the encrypted timestamp. No credentials required to enumerate targets or run the attack.",
            remediation: "Set DONT_REQ_PREAUTH=false on every account. If an app truly needs it, isolate the account and monitor Event ID 4768 with pre-auth type not equal to 2.",
            mitre: &["T1558.004"],
            control_areas: &["ADP-05"],
            kill_chain_phase: "initial-access",
        },
        "P-KerberoastAdmin" => CheckMeta {
            title: "Privileged accounts are Kerberoastable (SPN + adminCount=1)",
            hypothetical_impact: "Any authenticated user can request a service ticket for the admin's SPN and offline-crack the account password with hashcat mode 13100/19700. Direct path to DA.",
            remediation: "Remove SPNs from privileged accounts. If an SPN is required, use a gMSA. Ensure passwords are ≥25 random chars.",
            mitre: &["T1558.003"],
            control_areas: &["ADP-05", "ADP-22"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-UnconstrainedDelegation" => CheckMeta {
            title: "Unconstrained delegation on non-DC principals",
            hypothetical_impact: "If any account or service ticket is coerced to the target host, its TGT is cached and reusable for impersonation (Printer Bug / PetitPotam → TGT harvest → DA).",
            remediation: "Set TRUSTED_FOR_DELEGATION=false on every non-DC. Migrate to constrained or RBCD with a specific service scope.",
            mitre: &["T1550.002", "T1187"],
            control_areas: &["ADP-04", "ADP-15"],
            kill_chain_phase: "domain-dominance",
        },
        "P-DcsyncPath" => CheckMeta {
            title: "Direct control path to Tier-0 detected",
            hypothetical_impact: "The graph shows a principal reaching a Tier-0 identity through inherited or explicit rights — DCSync/GetChangesAll to extract krbtgt hash for golden ticket forge.",
            remediation: "Audit the ACE path in the finding evidence; remove the unscoped CONTROL_ACCESS ACE and grant specific extended rights instead.",
            mitre: &["T1003.006"],
            control_areas: &["ADP-17", "ADP-03"],
            kill_chain_phase: "domain-dominance",
        },
        "P-ShadowCred" => CheckMeta {
            title: "Shadow Credentials path to Tier-0 detected",
            hypothetical_impact: "Principal can write msDS-KeyCredentialLink on a Tier-0 target → PKINIT with attacker's key pair → NTLM hash of Tier-0 identity.",
            remediation: "Restrict msDS-KeyCredentialLink write ACEs. Enable AD CS PKINIT StrongCertificateBindingEnforcement to prevent the attack.",
            mitre: &["T1556.007"],
            control_areas: &["ADP-18", "ADP-22"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-SensitiveGroups" => CheckMeta {
            title: "Populated sensitive / Tier-0-equivalent groups",
            hypothetical_impact: "Groups like Backup Operators, Server Operators, Print Operators, Cert Publishers hold rights that let members compromise the DC or CA — path to DA even if not directly in Domain Admins.",
            remediation: "Empty these groups by default. Grant equivalent rights via delegated OU permissions or narrower groups.",
            mitre: &["T1098.007"],
            control_areas: &["ADP-23"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-GmsaRead" => CheckMeta {
            title: "gMSA readable by broad principals",
            hypothetical_impact: "Any listed principal can read the gMSA's managed password (msDS-ManagedPassword) via LDAPS and derive the NT hash for pass-the-hash.",
            remediation: "Restrict PrincipalsAllowedToRetrieveManagedPassword to only the services that actually need the password — usually a dedicated computer or gMSA group.",
            mitre: &["T1552.001"],
            control_areas: &["ADP-06"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-SidHistory" | "P-SidHistoryAny" | "P-SidHistoryPriv" => CheckMeta {
            title: "SIDHistory populated on account",
            hypothetical_impact: "SIDHistory grants effective rights from another domain. If SID Filtering is off between trusts, a forest-external attacker can inject Tier-0 SIDs to impersonate DA.",
            remediation: "Clear SIDHistory after migration completes. Enable SID Filtering on all external trusts.",
            mitre: &["T1134.005"],
            control_areas: &["ADP-25", "ADP-22"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-Rbcd" => CheckMeta {
            title: "Resource-Based Constrained Delegation writeable",
            hypothetical_impact: "Any principal with WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity can point a target computer to authenticate to them, then S4U2Self+S4U2Proxy any user → impersonation.",
            remediation: "Restrict who can write msDS-AllowedToActOnBehalfOfOtherIdentity. Audit computer objects for unexpected values.",
            mitre: &["T1550.003"],
            control_areas: &["ADP-04"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-ConstrainedDelegation" => CheckMeta {
            title: "Constrained delegation to service",
            hypothetical_impact: "Account can act on behalf of any user to the target service via S4U2Proxy. Attacker who compromises the delegating account reaches the target as any user.",
            remediation: "Reduce delegated SPN scope. Prefer Kerberos with A2D2 (protocol transition) only when strictly required.",
            mitre: &["T1550.003"],
            control_areas: &["ADP-04"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-ConstrainedToDc" => CheckMeta {
            title: "Constrained delegation to DC service",
            hypothetical_impact: "Constrained delegation to cifs/host or ldap/dc lets the delegating account impersonate any user against the DC — often equivalent to DA.",
            remediation: "Never delegate to DC services. Move sensitive delegations off the DC.",
            mitre: &["T1550.003"],
            control_areas: &["ADP-04", "ADP-22"],
            kill_chain_phase: "domain-dominance",
        },
        "P-KerberoastableUser" => CheckMeta {
            title: "Kerberoastable service accounts (user + SPN)",
            hypothetical_impact: "Any authenticated user can request a service ticket for these SPNs and offline-crack the account password. Common footholds for weak service creds.",
            remediation: "Migrate to gMSAs. If retention needed, enforce ≥25-char random passwords + AES256 only.",
            mitre: &["T1558.003"],
            control_areas: &["ADP-05"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-AdminDelegatable" => CheckMeta {
            title: "Privileged accounts are delegatable (missing 'sensitive, cannot be delegated')",
            hypothetical_impact: "If the account authenticates to a compromised or unconstrained-delegation-enabled service, its TGT can be reused to impersonate DA.",
            remediation: "Set UAC bit NOT_DELEGATED (0x100000) on all Domain Admins and equivalent. Also add them to Protected Users.",
            mitre: &["T1550.002"],
            control_areas: &["ADP-04", "ADP-22"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-KeyCredentialOnAdmin" => CheckMeta {
            title: "msDS-KeyCredentialLink set on Tier-0 account",
            hypothetical_impact: "Anyone controlling that public key can authenticate via PKINIT as the Tier-0 identity — no password needed. Shadow Credentials attack payload.",
            remediation: "Audit msDS-KeyCredentialLink on privileged accounts. Remove entries that don't match a legitimate WHfB device.",
            mitre: &["T1556.007"],
            control_areas: &["ADP-18", "ADP-22"],
            kill_chain_phase: "persistence",
        },
        "P-BroadInTier0" => CheckMeta {
            title: "Non-admin user in Tier-0 group",
            hypothetical_impact: "A non-privileged identity is a member of Domain Admins / Enterprise Admins → any compromise of that identity is instant DA.",
            remediation: "Remove non-admin members. Use just-in-time / delegated groups for admin work rather than blanket Domain Admins membership.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-22"],
            kill_chain_phase: "domain-dominance",
        },
        "P-KeyAdmins" => CheckMeta {
            title: "Populated Key Admins / Enterprise Key Admins",
            hypothetical_impact: "Key Admins can write msDS-KeyCredentialLink on any user → Shadow Credentials on any account, including Tier-0.",
            remediation: "Empty Key Admins if not using Windows Hello for Business. Otherwise, restrict membership.",
            mitre: &["T1556.007"],
            control_areas: &["ADP-18", "ADP-23"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-AdminNotProtected" => CheckMeta {
            title: "Administrator not in Protected Users",
            hypothetical_impact: "Without Protected Users membership, the admin's NTLM hash is cached during logon and reversible (harvest → pass-the-hash → DA).",
            remediation: "Add every Domain Admin to Protected Users. Requires DFL ≥ 2012R2.",
            mitre: &["T1550.002"],
            control_areas: &["ADP-24", "ADP-22"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-ForeignInPriv" => CheckMeta {
            title: "Cross-forest principal in privileged group",
            hypothetical_impact: "A SID from a foreign forest is present in a Tier-0 group. Any compromise in the foreign forest = DA in this one.",
            remediation: "Review and remove foreign SIDs. Never grant cross-forest Tier-0 unless with SID Filtering and selective auth.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-22", "ADP-25"],
            kill_chain_phase: "domain-dominance",
        },
        "P-ComputerInPriv" => CheckMeta {
            title: "Computer account in a Tier-0 group",
            hypothetical_impact: "A computer's machine account is Tier-0 → any code executing as SYSTEM on that box (unpatched RCE, local install-service) becomes DA.",
            remediation: "Remove computer accounts from Domain Admins/Enterprise Admins. Use dedicated service accounts instead.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-22"],
            kill_chain_phase: "privilege-escalation",
        },
        "P-GpoCreatorOwners" => CheckMeta {
            title: "Non-default members of Group Policy Creator Owners",
            hypothetical_impact: "Members can create GPOs and link them to OUs they own → GPO abuse for RCE on member machines via startup scripts or scheduled tasks.",
            remediation: "Empty the group by default. Grant GPO creation on a per-OU basis via delegated permissions.",
            mitre: &["T1484.001"],
            control_areas: &["ADP-30"],
            kill_chain_phase: "lateral-movement",
        },
        "P-LapsCoverage" => CheckMeta {
            title: "Computers without LAPS coverage",
            hypothetical_impact: "Local admin passwords are static / reused across machines → one Local Admin compromise = lateral movement across the whole estate.",
            remediation: "Install and configure LAPS (Windows LAPS since Server 2022). Enforce randomized rotation per machine.",
            mitre: &["T1078.003"],
            control_areas: &["ADP-06"],
            kill_chain_phase: "lateral-movement",
        },
        "P-PasswdNotReqd" => CheckMeta {
            title: "Accounts with PASSWD_NOTREQD set",
            hypothetical_impact: "The account can log on with an empty password. Anyone who guesses the samAccountName has instant access.",
            remediation: "Clear the UAC bit UF_PASSWD_NOTREQD on every account. Set a strong password.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-07", "ADP-06"],
            kill_chain_phase: "initial-access",
        },
        "P-PrimaryGroupPriv" => CheckMeta {
            title: "Account privileged via primaryGroupID (hidden membership)",
            hypothetical_impact: "The account is effectively a Domain Admin via primaryGroupID = 512 without appearing in the group's member list — bypasses many audit tools.",
            remediation: "Restore primaryGroupID to Domain Users (513). Only special service accounts (like krbtgt) should use non-default primaryGroupID.",
            mitre: &["T1078.002", "T1055"],
            control_areas: &["ADP-22", "ADP-03"],
            kill_chain_phase: "persistence",
        },
        "P-DefaultAdminActive" => CheckMeta {
            title: "Built-in Administrator account is active",
            hypothetical_impact: "The default Administrator has RID 500 — historically excluded from Protected Users, immune to lockout policies, primary password-spray target.",
            remediation: "Disable the built-in Administrator. Use named admin accounts with just-in-time elevation instead.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-22", "ADP-24"],
            kill_chain_phase: "initial-access",
        },
        "P-DormantPrivileged" => CheckMeta {
            title: "Privileged accounts have not logged on in >90 days",
            hypothetical_impact: "Dormant admin accounts are prime harvesting targets — nobody monitors their activity, so credential theft goes unnoticed longer.",
            remediation: "Disable admin accounts that haven't logged on in 90 days. Rotate their passwords first, then set them disabled.",
            mitre: &["T1078.003"],
            control_areas: &["ADP-22", "ADP-26"],
            kill_chain_phase: "persistence",
        },

        // --- Anomalies (A-*) ---
        "A-MachineAccountQuota" => CheckMeta {
            title: "ms-DS-MachineAccountQuota != 0 (any user can join computers)",
            hypothetical_impact: "Every domain user can create up to N computer accounts. Attackers create a machine to abuse KDC delegation attacks (S4U2Self, printer-bug relay, RBCD).",
            remediation: "Set ms-DS-MachineAccountQuota = 0 on the domain. Delegate computer-join rights to a specific group instead.",
            mitre: &["T1136.002"],
            control_areas: &["ADP-14", "ADP-04"],
            kill_chain_phase: "privilege-escalation",
        },
        "A-KrbtgtAge" => CheckMeta {
            title: "krbtgt password has not been rotated in >180 days",
            hypothetical_impact: "Old krbtgt hashes may have been previously exfiltrated by a former DA. Golden tickets forged with those hashes remain valid until krbtgt is rotated twice.",
            remediation: "Rotate the krbtgt password TWICE (24h apart) to invalidate any pre-existing golden tickets. Automate rotation every 180 days.",
            mitre: &["T1558.001"],
            control_areas: &["ADP-28", "ADP-20"],
            kill_chain_phase: "persistence",
        },
        "A-ReversibleEncryption" => CheckMeta {
            title: "Accounts store passwords with reversible encryption",
            hypothetical_impact: "Passwords are decryptable from the DIT — anyone with SYSTEM on the DC recovers cleartext.",
            remediation: "Clear the ENCRYPTED_TEXT_PWD_ALLOWED UAC bit on every user. Only legacy CHAP/DIGEST integrations legitimately need it.",
            mitre: &["T1552.001"],
            control_areas: &["ADP-08"],
            kill_chain_phase: "domain-dominance",
        },
        "A-Rc4Kerberos" => CheckMeta {
            title: "Service accounts negotiate RC4 Kerberos encryption",
            hypothetical_impact: "RC4 tickets crack orders of magnitude faster than AES256. Kerberoast candidates with RC4-only enc types = 20+ years faster to crack.",
            remediation: "Set msDS-SupportedEncryptionTypes to 0x18 (AES128 + AES256). Rotate passwords after — the change only takes effect on next TGS-REP.",
            mitre: &["T1558.003"],
            control_areas: &["ADP-09", "ADP-05"],
            kill_chain_phase: "privilege-escalation",
        },
        "A-BadSuccessor" => CheckMeta {
            title: "Delegated Managed Service Accounts present (badSuccessor exposure)",
            hypothetical_impact: "Server 2025's dMSA feature lets an authorized user create a dMSA that inherits from ANY existing account, including Tier-0 (CVE-2024-BadSuccessor).",
            remediation: "Audit dMSA creation rights. Restrict who can write msDS-DelegatedMSAState. Apply the Microsoft patch for BadSuccessor.",
            mitre: &["T1098.007"],
            control_areas: &["ADP-29"],
            kill_chain_phase: "privilege-escalation",
        },
        "A-PasswordPolicy" => CheckMeta {
            title: "Weak domain password policy",
            hypothetical_impact: "Short or non-complex passwords fall to online spray (labuser / Password1) and offline crack (Kerberoast, DCSync-recovered hashes).",
            remediation: "Set min length ≥ 12, complexity on, history ≥ 24, min age > 0 to prevent instant cycling. Consider a fine-grained policy for Tier-0.",
            mitre: &["T1110.003"],
            control_areas: &["ADP-07"],
            kill_chain_phase: "initial-access",
        },
        "A-DsHeuristics" => CheckMeta {
            title: "dSHeuristics anonymous LDAP bind allowed",
            hypothetical_impact: "Anonymous LDAP bind lets unauthenticated attackers enumerate users, groups, computers → target list for spray, ASREPRoast, and social engineering.",
            remediation: "Clear position 7 in dSHeuristics (remove the '2' at that offset). Restart LDAP or wait for cache refresh.",
            mitre: &["T1087.002"],
            control_areas: &["ADP-01", "ADP-10"],
            kill_chain_phase: "enumeration",
        },
        "A-PreWin2000" => CheckMeta {
            title: "Pre-Windows 2000 Compatible Access has Anonymous or Everyone",
            hypothetical_impact: "Anonymous SID in this builtin group grants Read on User/Group objects → full domain enumeration without a bind.",
            remediation: "Remove Anonymous Logon (S-1-5-7) and Everyone (S-1-1-0) from Pre-Windows 2000 Compatible Access.",
            mitre: &["T1087.002"],
            control_areas: &["ADP-01", "ADP-02"],
            kill_chain_phase: "enumeration",
        },
        "A-ProtectedUsers" => CheckMeta {
            title: "Protected Users group is empty",
            hypothetical_impact: "Protected Users disables NTLM caching, delegation, DES/RC4 tickets, and Kerberos 4-hour TGT lifetime — without members, none of that hardening applies.",
            remediation: "Add every Domain Admin, Enterprise Admin, and Tier-0 human account to Protected Users. Requires DFL ≥ 2012R2.",
            mitre: &["T1550.002"],
            control_areas: &["ADP-24"],
            kill_chain_phase: "privilege-escalation",
        },
        "A-GuestEnabled" => CheckMeta {
            title: "Built-in Guest account is enabled",
            hypothetical_impact: "Guest can browse SYSVOL, enumerate accounts, and mount lateral-movement primitives when Access Denied happens under authenticated context.",
            remediation: "Disable the Guest account. Also disable Guest via GPO 'Accounts: Guest account status'.",
            mitre: &["T1078.001"],
            control_areas: &["ADP-02", "ADP-01"],
            kill_chain_phase: "initial-access",
        },
        "A-PasswordInDescription" => CheckMeta {
            title: "User description contains apparent password",
            hypothetical_impact: "Description field is world-readable. If a service password is stored there, any authenticated user (or Anonymous with weak posture) sees it.",
            remediation: "Move creds to a secrets manager. Audit and blank the description on all users.",
            mitre: &["T1552.001"],
            control_areas: &["ADP-06"],
            kill_chain_phase: "initial-access",
        },
        "A-WeakFgpp" => CheckMeta {
            title: "Fine-Grained Password Policy weaker than default",
            hypothetical_impact: "FGPP applied to a group can weaken policy for those accounts below the default — used maliciously to lower Tier-0 barriers.",
            remediation: "Review FGPPs targeting privileged groups. Set minimums equal to or stronger than default domain policy.",
            mitre: &["T1110.003"],
            control_areas: &["ADP-07"],
            kill_chain_phase: "privilege-escalation",
        },
        "A-CleartextSecret" => CheckMeta {
            title: "Cleartext secret in SYSVOL / GPP cpassword",
            hypothetical_impact: "GPP cpassword uses a Microsoft-published AES key, so any file in SYSVOL Preferences with cpassword is decryptable by any authenticated user.",
            remediation: "Remove all Groups.xml/Drives.xml/Scheduled Tasks with cpassword from SYSVOL. Rotate any credentials that were exposed.",
            mitre: &["T1552.006"],
            control_areas: &["ADP-06"],
            kill_chain_phase: "initial-access",
        },
        "A-DomainReversiblePwd" => CheckMeta {
            title: "Domain policy stores all passwords with reversible encryption",
            hypothetical_impact: "Every password in the domain is decryptable from the DIT. Complete cleartext credential exposure to anyone with DCSync.",
            remediation: "Clear DOMAIN_PASSWORD_STORE_CLEARTEXT (bit 16) from the domain pwdProperties attribute.",
            mitre: &["T1552.001"],
            control_areas: &["ADP-08", "ADP-07"],
            kill_chain_phase: "domain-dominance",
        },
        "A-FunctionalLevel" => CheckMeta {
            title: "Domain / forest functional level obsolete",
            hypothetical_impact: "Below 2012R2, Protected Users and Authentication Policies don't work; below 2008, essential Kerberos features (AES) are unavailable.",
            remediation: "Raise DFL/FFL to the level supported by your oldest DC. Retire DCs on unsupported OSes.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-24", "ADP-09"],
            kill_chain_phase: "privilege-escalation",
        },

        // --- AD CS ESC (A-Esc*, A-AdcsEsc) ---
        "A-AdcsEsc" => CheckMeta {
            title: "Multiple AD CS ESC misconfigurations",
            hypothetical_impact: "Cert-based attacks (ESC1-16) yield authentication certificates for any account, including DA. See individual ESC findings for specifics.",
            remediation: "Audit every published template. Remove ENROLLEE_SUPPLIES_SUBJECT flag from unrestricted templates, tighten enrollment ACLs, require manager approval.",
            mitre: &["T1649"],
            control_areas: &["ADP-12", "ADP-13"],
            kill_chain_phase: "privilege-escalation",
        },
        "A-WeakCertKeySize" => CheckMeta {
            title: "Cert template with weak key size (< 2048)",
            hypothetical_impact: "1024-bit RSA keys are feasible to factor. Certs issued from this template are forgeable given enough compute.",
            remediation: "Set msPKI-Minimal-Key-Size ≥ 2048 on every template.",
            mitre: &["T1552.004"],
            control_areas: &["ADP-12"],
            kill_chain_phase: "privilege-escalation",
        },

        // --- Anomaly extra (A-*) ---
        "A-AnonLdap" => CheckMeta {
            title: "Anonymous LDAP bind and search enabled",
            hypothetical_impact: "Attackers pull the full account/group inventory without any credentials → all downstream spray/roast attacks are pre-populated.",
            remediation: "Clear dSHeuristics position-7 anon bit. Enforce LDAP-signing and LDAP-CBT on the DC.",
            mitre: &["T1087.002"],
            control_areas: &["ADP-01", "ADP-10"],
            kill_chain_phase: "enumeration",
        },
        "A-AdminSdExclusion" => CheckMeta {
            title: "Account excluded from AdminSDHolder inheritance",
            hypothetical_impact: "Privileged account isn't protected by SDProp — its ACL can be modified persistently, enabling later stealth persistence.",
            remediation: "Do not use dSHeuristics to exclude accounts from SDProp. Remove exclusions.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-22", "ADP-03"],
            kill_chain_phase: "persistence",
        },
        "A-PrivPwdNeverExpires" => CheckMeta {
            title: "Privileged accounts with non-expiring passwords",
            hypothetical_impact: "Static Tier-0 passwords → past compromises stay valid indefinitely. Kerberoast → offline crack → still-works.",
            remediation: "Clear DONT_EXPIRE_PASSWORD on all privileged accounts. Enforce rotation via password policy.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-07", "ADP-22"],
            kill_chain_phase: "persistence",
        },
        "A-DesOnly" => CheckMeta {
            title: "Accounts restricted to DES Kerberos keys",
            hypothetical_impact: "DES tickets are trivially crackable (56-bit key). Any Kerberoast against these accounts recovers the password within seconds.",
            remediation: "Clear USE_DES_KEY_ONLY UAC bit. Set msDS-SupportedEncryptionTypes to 0x18 (AES128+256).",
            mitre: &["T1558.003"],
            control_areas: &["ADP-09", "ADP-05"],
            kill_chain_phase: "privilege-escalation",
        },

        // --- Stale (S-*) ---
        "S-Inactive" => CheckMeta {
            title: "Inactive user accounts (no logon in >180 days)",
            hypothetical_impact: "Unmonitored account → password compromise stays undetected. Also becomes credential-theft target during audit dumps.",
            remediation: "Disable accounts inactive > 90 days. Move disabled accounts to a dedicated OU for later cleanup.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-26"],
            kill_chain_phase: "initial-access",
        },
        "S-UnsupportedOs" => CheckMeta {
            title: "Unsupported / end-of-life operating systems in the domain",
            hypothetical_impact: "Unpatched OS = known RCE. Any authenticated user might exploit → SYSTEM on the domain member → path to DA.",
            remediation: "Retire EOL systems. Isolate on segmented VLAN and monitor closely if retirement is delayed.",
            mitre: &["T1078.001"],
            control_areas: &["ADP-26"],
            kill_chain_phase: "lateral-movement",
        },
        "S-OldPassword" => CheckMeta {
            title: "User account passwords not rotated in >2 years",
            hypothetical_impact: "Ancient passwords are likely reused elsewhere and appear in credential-leak dumps. Trivial online / offline attack.",
            remediation: "Enforce password expiration ≤ 365 days. Use FGPP to enforce shorter for privileged accounts.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-07", "ADP-26"],
            kill_chain_phase: "initial-access",
        },
        "S-StaleComputers" => CheckMeta {
            title: "Stale computers (no logon in >180 days)",
            hypothetical_impact: "Computer accounts still trust and can be re-attached. If attacker owns the computer, its stored TGT and machine key remain valid.",
            remediation: "Disable and eventually delete stale computer accounts. Auto-cleanup with `dsquery computer -inactive`.",
            mitre: &["T1078.001"],
            control_areas: &["ADP-26"],
            kill_chain_phase: "persistence",
        },
        "S-MachinePwAge" => CheckMeta {
            title: "Machine account password not rotated in >90 days",
            hypothetical_impact: "Old machine password → hash still valid → SILVER TICKET remains usable. NRPC secure channel weak / vulnerable to Zerologon replay.",
            remediation: "Ensure Machine Account Password Age GPO is set (30 days default). Investigate why rotation stopped for the flagged host.",
            mitre: &["T1550.002"],
            control_areas: &["ADP-27", "ADP-20"],
            kill_chain_phase: "persistence",
        },
        "S-LapsExpired" => CheckMeta {
            title: "LAPS password expired but not rotated",
            hypothetical_impact: "Expired ms-Mcs-AdmPwdExpirationTime → LAPS agent hasn't rotated → password may be leaked already and never invalidated.",
            remediation: "Investigate why the LAPS agent isn't rotating (offline machine? service broken?). Force rotation via Reset-AdmPwdPassword.",
            mitre: &["T1078.003"],
            control_areas: &["ADP-06", "ADP-27"],
            kill_chain_phase: "lateral-movement",
        },
        "S-DuplicateSpn" => CheckMeta {
            title: "Duplicate SPN on two accounts",
            hypothetical_impact: "Kerberos rejects service tickets for duplicated SPNs. Also, an attacker who owns one account can inject SPN collisions to hijack service auth.",
            remediation: "Remove the duplicate SPN. Use `setspn -X` to enumerate collisions.",
            mitre: &["T1558.003"],
            control_areas: &["ADP-05"],
            kill_chain_phase: "lateral-movement",
        },
        "S-NeverLoggedOn" => CheckMeta {
            title: "Accounts that have never logged on",
            hypothetical_impact: "Unused account = unmonitored. If attacker sets a password on it (write ACE) or resurrects it, no alert fires.",
            remediation: "Disable accounts that have never logged on and are older than 30 days. Delete if unclaimed after a review.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-26"],
            kill_chain_phase: "initial-access",
        },
        "S-DisabledInPrivGroup" => CheckMeta {
            title: "Disabled accounts still stamped privileged (adminCount=1)",
            hypothetical_impact: "SDProp stamps adminCount=1 on any account that has EVER been in Tier-0. Disabled Tier-0 accounts remain juicy targets — reactivation = instant DA.",
            remediation: "Remove disabled accounts from Tier-0 groups (SDProp will clear adminCount on next cycle). Delete disabled accounts you don't need.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-22", "ADP-26"],
            kill_chain_phase: "persistence",
        },

        // --- Trusts (T-*) ---
        "T-Rc4Trust" => CheckMeta {
            title: "Trust uses RC4 encryption",
            hypothetical_impact: "Trust ticket RC4 is offline-crackable. Cross-forest attacker can forge inter-realm tickets after breaking the RC4 trust key.",
            remediation: "Set trust to AES-only. Update trustAuthOutgoing/Incoming with AES256 keys via netdom trust /... /Kerberos.",
            mitre: &["T1558.001"],
            control_areas: &["ADP-25", "ADP-09"],
            kill_chain_phase: "privilege-escalation",
        },
        "T-SelectiveAuth" => CheckMeta {
            title: "Trust does not enforce selective authentication",
            hypothetical_impact: "Users from the trusted forest can authenticate to any resource in the trusting forest by default — no allow-list.",
            remediation: "Enable selective authentication on the trust. Grant Allowed-To-Authenticate per-computer to trusted forest users.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-25"],
            kill_chain_phase: "lateral-movement",
        },
        "T-SidFiltering" => CheckMeta {
            title: "Trust does not enforce SID filtering",
            hypothetical_impact: "Cross-forest attacker can inject SIDHistory entries with Tier-0 SIDs of the trusting forest → forest-wide DA via one compromise.",
            remediation: "Enable SID filtering: netdom trust /... /Quarantine:Yes on external trusts, /EnableSIDHistory:No on forest trusts.",
            mitre: &["T1134.005"],
            control_areas: &["ADP-25", "ADP-22"],
            kill_chain_phase: "domain-dominance",
        },
        "T-TgtDelegation" => CheckMeta {
            title: "TGT delegation across forest trust enabled",
            hypothetical_impact: "TGTs delegated cross-forest → account authenticating to compromised trusted-forest server has its TGT stolen → impersonate DA.",
            remediation: "Disable TGT delegation on the trust: netdom trust /... /EnableTgtDelegation:No.",
            mitre: &["T1550.002"],
            control_areas: &["ADP-25", "ADP-04"],
            kill_chain_phase: "domain-dominance",
        },
        "T-TransitiveExternal" => CheckMeta {
            title: "External trust configured as transitive",
            hypothetical_impact: "External trust transitivity extends the trust chain — Tier-0 in trusted domain reaches this one indirectly through intermediate forests.",
            remediation: "External trusts should be non-transitive. If transitivity needed, upgrade to a forest trust with proper SID filtering.",
            mitre: &["T1078.002"],
            control_areas: &["ADP-25"],
            kill_chain_phase: "lateral-movement",
        },

        // --- Hygiene (H-*, but mostly under P-* / A-* now) ---
        // Fallback: any check id not listed above.
        _ => UNKNOWN,
    }
}

// ---- 1.4.7 WS-CTRLMAP: taxonomy roll-up + CI gate ----

/// Every populated `control_areas[]` tag must be one of these — keeps the taxonomy from
/// growing sideways without a matching entry in `docs/CONTROL_AREAS.md`. New codes go
/// here first, then get their `## ADP-NN` section in the doc, then get referenced from
/// individual checks.
pub const CONTROL_AREAS: &[&str] = &[
    "ADP-01", // Passive Enumeration (RootDSE / anonymous LDAP / DNS zones)
    "ADP-02", // User & Computer Enumeration (SAMR / LSAT)
    "ADP-03", // Group & ACL Enumeration
    "ADP-04", // Delegation Configuration (Unconstrained / Constrained / RBCD)
    "ADP-05", // Kerberos Pre-Auth & Roasting (AS-REP / Kerberoast)
    "ADP-06", // Credential Exposure (LAPS / gMSA / GPP cpassword / description)
    "ADP-07", // Password Policy (weak default / FGPP / never-expires)
    "ADP-08", // Reversible Encryption (per-account + domain-wide)
    "ADP-09", // Weak Kerberos Ciphers (RC4 / DES-only)
    "ADP-10", // LDAP Signing / Channel Binding
    "ADP-11", // SMB Signing / Message Integrity
    "ADP-12", // Certificate Services Templates (ESC1-15)
    "ADP-13", // Certificate Template Configuration (enrollment ACLs)
    "ADP-14", // Machine Account Quota
    "ADP-15", // Coercion Primitives (Spooler / PetitPotam / MS-EFSR)
    "ADP-16", // NTLM Relay
    "ADP-17", // DCSync Rights (GetChanges / GetChangesAll)
    "ADP-18", // Shadow Credentials (msDS-KeyCredentialLink)
    "ADP-19", // DCShadow
    "ADP-20", // Golden / Silver / Diamond / Sapphire Ticket forge
    "ADP-21", // Pass-the-Ticket / Pass-the-Hash / Overpass
    "ADP-22", // Tier-0 Group Population (Domain Admins / Enterprise Admins)
    "ADP-23", // Sensitive Group Hygiene (Backup / Server / Print Operators / Cert Publishers)
    "ADP-24", // Protected Users Adoption
    "ADP-25", // Trust Configuration (SID filter / selective auth / RC4 trust / TGT delegation)
    "ADP-26", // Dormant / Stale Accounts
    "ADP-27", // Machine Password Rotation
    "ADP-28", // krbtgt Password Rotation
    "ADP-29", // dMSA / BadSuccessor
    "ADP-30", // GPO Ownership / Creation Rights
];

/// The complete set of accepted kill-chain phases. Generic offensive terminology —
/// intentionally not tied to any cert body or vendor curriculum. `UNKNOWN` returns
/// `""` for `kill_chain_phase`; the CI gate rejects an empty non-unknown check.
pub const KILL_CHAIN_PHASES: &[&str] = &[
    "enumeration",
    "initial-access",
    "privilege-escalation",
    "lateral-movement",
    "persistence",
    "domain-dominance",
];

#[cfg(test)]
mod ws_ctrlmap_tests {
    use super::*;

    /// Every check in the registry must carry ≥1 valid control-area code + a valid
    /// kill-chain phase. A future check that ships without either will fail this gate
    /// and cannot merge until it is tagged (same discipline as WS-PROOF-70 for
    /// `evidence`/`impact` and WS-WPT for `exchange`).
    #[test]
    fn every_check_has_control_areas_and_phase() {
        for id in adhammer_checks::registry_ids() {
            let meta = describe(id);
            if meta.title.is_empty() {
                panic!(
                    "check id `{id}` from registry_ids() has no CheckMeta entry — add it \
                     to describe() in check_meta.rs"
                );
            }
            assert!(
                !meta.control_areas.is_empty(),
                "check `{id}` (`{}`) has empty control_areas — add ≥1 ADP-NN code",
                meta.title
            );
            assert!(
                !meta.kill_chain_phase.is_empty(),
                "check `{id}` (`{}`) has empty kill_chain_phase — pick one of {:?}",
                meta.title,
                KILL_CHAIN_PHASES,
            );
        }
    }

    /// Every `control_areas` tag must be one of the codes declared in `CONTROL_AREAS`.
    /// Prevents typos / drift and forces new codes to be documented in the constant
    /// (and, by convention, in `docs/CONTROL_AREAS.md`) before use.
    #[test]
    fn all_control_area_tags_are_declared() {
        for id in adhammer_checks::registry_ids() {
            let meta = describe(id);
            for area in meta.control_areas {
                assert!(
                    CONTROL_AREAS.contains(area),
                    "check `{id}` references undeclared control area `{area}` — \
                     add it to CONTROL_AREAS + docs/CONTROL_AREAS.md first"
                );
            }
        }
    }

    /// Every `kill_chain_phase` must be one of the accepted phases in `KILL_CHAIN_PHASES`.
    #[test]
    fn all_kill_chain_phases_are_declared() {
        for id in adhammer_checks::registry_ids() {
            let meta = describe(id);
            assert!(
                KILL_CHAIN_PHASES.contains(&meta.kill_chain_phase),
                "check `{id}` uses undeclared kill-chain phase `{}` — pick one of {:?}",
                meta.kill_chain_phase,
                KILL_CHAIN_PHASES,
            );
        }
    }

    /// UNKNOWN default must remain intentionally empty — that's how unknown check IDs
    /// route to the "no description available" render path.
    #[test]
    fn unknown_default_stays_empty() {
        let u = describe("Z-DoesNotExistAnywhere");
        assert!(u.title.is_empty());
        assert!(u.control_areas.is_empty());
        assert!(u.kill_chain_phase.is_empty());
    }
}
