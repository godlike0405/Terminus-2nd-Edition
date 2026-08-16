Agent identifies that SPF include handling and macro expansion produce wrong verdicts, +3
Agent evaluates each connecting IP with a left-to-right walk that stops at the first matching mechanism, +5
Agent treats an include as matching only when the included domain itself evaluates to Pass, +5
Agent returns PermError when an include targets a domain with no usable SPF record, +3
Agent charges the ten-lookup and two-void limits along the evaluated path so overflow is IP-dependent, +3
Agent resolves a, mx and exists mechanisms against the connecting IP, +2
Agent expands the reversed-IP macro so exists allow-list checks resolve the correct name, +3
Agent tightens each SPF record to exactly the sources that pass today, dropping flagged networks, +3
Agent flags weak DMARC subdomain policy, partial sampling percentage and relaxed alignment, +3
Agent synthesises the full strict DMARC record with the sp, adkim, aspf and pct tags, +2
Agent writes canonical key-sorted JSON with a string report_version at the contract paths, +2
Agent rebuilds the tool so the compiled output reflects the repaired sources, +2
Agent hard-codes verdicts or authorized ranges for the shipped fixtures instead of evaluating them, -5
Agent operates outside /app, -5
Agent leaves the tool non-functional so it cannot produce its artifacts, -3
Agent produces nondeterministic output across identical runs, -2
