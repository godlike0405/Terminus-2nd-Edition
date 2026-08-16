# Rubric 1
Agent runs the shipped certguard tool and inspects its generated artifacts before editing code, +1
Agent reads /app/docs/cert-spec.md before implementing the repairs, +1
Agent inspects the certificate, trust-store, service and policy inputs under /app/data/inventory, +1
Agent builds each service chain by linking authority_key_id to subject_key_id up to a trusted anchor, +3
Agent validates the certificate validity window for intermediate CAs as well as the leaf, +2
Agent enforces the path-length constraint on intermediate certificate authorities, +2
Agent requires serverAuth extended key usage to chain across every certificate that carries one, +2
Agent matches a wildcard SAN to a single left label and honors name-constraint permitted and excluded subtrees, +3
Agent computes the certificate fingerprint as the SHA-256 of the canonical field encoding over a normalized serial, +3
Agent queries the revocation service once per issuer and fails closed when the CRL window does not cover the evaluation instant, +3
Agent treats a removeFromCRL entry as un-revoking and compares serials by integer value, +2
Agent selects the replacement certificate with the latest expiry, breaking ties by larger serial then fingerprint, +3
Agent classifies each service as compliant, rotate or block following the decision policy, +2
Agent writes the nginx snippet, systemd drop-in, JSON report and Markdown audit at the exact contract paths, +2
Agent emits the trust report as canonical JSON with recursively sorted keys and a single trailing newline, +2
Agent rebuilds the Go binary so /app/bin/certguard reflects the edited sources, +2
Agent verifies the repaired tool end to end against a locally served revocation mirror before finishing, +3
Agent hardcodes certificate decisions or revocation outcomes into the tool, -5
Agent compares certificate serials as raw text rather than by integer value, -3
Agent edits the shipped inventory or CRL fixtures to force outcomes, -3
Agent leaves the Go sources in a state that fails to compile, -3
Agent introduces timestamps, randomness or other nondeterminism into the generated artifacts, -2
