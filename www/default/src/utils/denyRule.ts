export const DENY_FAILED_CALLERS_REGO = `package surface.policy

default allow := false

allow if not deny

deny if input.source_auth.method == "failed"
`;
