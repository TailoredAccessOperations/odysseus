#!/usr/bin/env bash
# proctree.sh — debug view of the odysseus stack: uvicorn :7860, cloudflared,
# wrangler dev :8793, and any Homebrew build the launcher is waiting on.
# Usage: scripts/proctree.sh [log-lines]
set -u
export PATH="$HOME/.homebrew/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
N="${1:-15}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PAT='uvicorn|launcher\\.py|odysseus/app\\.py|cloudflared|wrangler|workerd|[/ ]brew[ ]|Homebrew/Library|[/ ]make( |$)|[/ ]pip3?( |$)|python@3\\.11'

hdr() { printf '\n== %s ==\n' "$1"; }

hdr "process tree (odysseus stack, with ancestors and descendants)"
ps -axo pid=,ppid=,etime=,command= | awk -v pat="$PAT" '
  { pid=$1; ppid[pid]=$2; et[pid]=$3; $1=$2=$3=""; sub(/^ +/,""); cmd[pid]=$0; kids[ppid[pid]]=kids[ppid[pid]] " " pid; order[++n]=pid }
  END {
    for (i=1;i<=n;i++){ p=order[i]; if (cmd[p] ~ pat && cmd[p] !~ /proctree|awk/) { hit[p]=1; q=ppid[p]; while (q>1 && !(q in keep)) { keep[q]=1; q=ppid[q] } } }
    for (p in hit) mark(p)
    for (i=1;i<=n;i++){ p=order[i]; if ((p in keep) && !((ppid[p]) in keep)) show(p,0) }
  }
  function mark(p,  k,a,j){ keep[p]=1; k=split(kids[p],a," "); for(j=1;j<=k;j++) mark(a[j]) }
  function show(p,d,  k,a,j,c){ c=cmd[p]; if (length(c)>140) c=substr(c,1,140) "…"
    printf "%s%-6s %-11s %s%s\n", sprintf("%*s",d*2,""), p, et[p], c, (p in hit)?"  <==":""
    k=split(kids[p],a," "); for(j=1;j<=k;j++) if (a[j] in keep) show(a[j],d+1) }'

hdr "listening ports (7860 app, 8793 wrangler dev, cloudflared metrics)"
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR==1 || /:7860|:8793|cloudflar|workerd|python|uvicorn/'

hdr "health"
printf 'app  127.0.0.1:7860 -> %s\n' "$(c=$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1:7860/); [ "$c" = 000 ] && echo down || echo "$c")"
printf 'dev  127.0.0.1:8793 -> %s\n' "$(c=$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1:8793/); [ "$c" = 000 ] && echo down || echo "$c")"
printf 'cert.pem: %s\n' "$([ -f "$HOME/.cloudflared/cert.pem" ] && echo present || echo MISSING - run: cloudflared tunnel login)"
command -v cloudflared >/dev/null && cloudflared tunnel info odysseus 2>/dev/null | tail -n +1 | head -8

hdr "log tails"
for f in "$ROOT"/logs/*.log /tmp/cf-login.log; do
  [ -f "$f" ] || continue
  printf -- '--- %s\n' "$f"; tail -n "$N" "$f"
done
