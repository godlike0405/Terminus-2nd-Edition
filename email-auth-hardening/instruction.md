Our brand-protection team keeps finding spoofed mail that sails through inbox
filters wearing our domains in the From address, and every post-incident review
blames the same thing: we cannot actually tell which senders our published SPF
records authorize, so our records stay loose and our DMARC stays at `p=none`.
`mailguard` in `/app` is the auditor meant to settle this — point it at the estate's
domains and a batch of observed inbound connections and it should replay each
connection through the real SPF check, expose exactly where the authentication
posture is weak, and emit hardened records we can push to the zone.

Right now its verdicts can't be trusted. It doesn't follow the SPF `include` rules
the way a mail receiver does — an `include` authorizes a sender only when it itself
evaluates to a pass, and an include of a domain with no SPF record is a hard error,
but the tool waves both through — so senders that should fail come back authorized.
It mis-expands the macro used by reversed-IP allow-lists, so those checks match the
wrong name. Its DMARC verdict overlooks weak subdomain policies, partial rollout and
relaxed alignment. And the records and report it writes don't land where or how they
are supposed to. The result looks clean while leaving our domains spoofable.

`mailguard` resolves records through a DNS resolver and pulls flagged sending
networks from a spoof-intel feed, both over HTTP. For every observed connection it
must evaluate the connecting IP against its domain's SPF record with the full
check-host walk — matching mechanisms left to right and stopping at the first match,
recursing through `include` and `redirect`, resolving `a`/`mx`/`exists` (expanding
macros) and honouring the ten-lookup and two-void limits along the path taken, so a
record can pass one sender and hard-error another. It must flag every SPF and DMARC
weakness, tighten each SPF record down to exactly the sources that legitimately pass
today (dropping any the feed flags), and synthesise a strict DMARC record — then
write the hardened records, a JSON report and a Markdown audit. The exact evaluation
rules, lookup accounting, macro semantics, weakness codes, hardening and feed
behaviour, and the paths and byte layout of every artifact are specified in
`/app/docs/hardening-spec.md`. Make `mailguard` produce the correct artifacts for
whatever domains, connections, DNS data and feed it is pointed at, and keep it
runnable as `/app/bin/mailguard`.
