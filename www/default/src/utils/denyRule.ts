const denyFailedCallers = (pkg: string) => `package ${pkg}

default allow := false

allow if not deny

deny if input.source_auth.method == "failed"
`;

export const DENY_FAILED_CALLERS_REGO = denyFailedCallers('surface.policy');

export const GATEWAY_DENY_FAILED_CALLERS_REGO = denyFailedCallers('gateway.policy');

export const DENY_FAILED_CALLERS_CONDITION = 'not input.source_auth.method == "failed"';
