Feature: Credential rules when saving through the admin API
  The admin API refuses to store a credential provider that sends its token request over
  plain http, and refuses to give a tenant's credential provider or surface a secret that is
  appliance-wide or belongs to another tenant. An update cannot remove the client references
  an OAuth credential provider needs, even from a provider that keeps a plain http token
  endpoint. A surface that already stores an appliance-wide secret keeps it while tenant
  credential isolation only warns, and is refused once the gateway enforces it. A surface
  whose stored Target credential, on the Target or a Transit Point, breaks the https or caller
  rule saves again unchanged and the save answers with a Warning header for each breach; once
  that credential is edited it is checked as new, and refused while the rule is enforced.

  Scenario: A credential provider with an http token endpoint is refused and not stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "provider-id-secret"
    And the appliance holds the secret "provider-password-secret"
    When the operator creates the credential provider "plain-http" with token endpoint "http://192.0.2.1/token" using secrets "provider-id-secret" and "provider-password-secret"
    Then the admin API response status is 400
    And the admin API error response mentions "token_endpoint must be an https URL"
    And no credential provider "plain-http" is stored

  Scenario: A credential provider with an https token endpoint is stored
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "provider-id-secret"
    And the appliance holds the secret "provider-password-secret"
    When the operator creates the credential provider "secure-https" with token endpoint "https://192.0.2.1/token" using secrets "provider-id-secret" and "provider-password-secret"
    Then the admin API response status is 201
    And the credential provider "secure-https" is stored

  Scenario: A stored credential provider with an http token endpoint is refused an update that clears its client secret
    Given an A2A surface targeting managed agent "bravo"
    And the gateway authenticates to the managed agent with a client credentials provider
    And the credential provider has a plain http token endpoint
    When the operator clears the credential provider's client secret
    Then the admin API response status is 400
    And the admin API error response mentions "client_id_secret_ref and client_secret_secret_ref are required for OAuth providers"
    And the stored credential provider still has the client secret "bdd-target-client-secret"

  Scenario: A tenant credential provider cannot reference appliance-wide secrets
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "appliance-id-secret"
    And the appliance holds the secret "appliance-password-secret"
    When the operator creates the credential provider "tenant-cc" for tenant "tenant-a" using secrets "appliance-id-secret" and "appliance-password-secret"
    Then the admin API response status is 400
    And the admin API error response mentions "Secret reference is not accessible"
    And no credential provider "tenant-cc" is stored

  Scenario: A tenant credential provider cannot reference another tenant's secrets
    Given the operator can use the admin API and no surface is configured for route "/example"
    And tenant "tenant-b" holds the secret "other-id-secret"
    And tenant "tenant-b" holds the secret "other-password-secret"
    When the operator creates the credential provider "tenant-cc" for tenant "tenant-a" using secrets "other-id-secret" and "other-password-secret"
    Then the admin API response status is 400
    And the admin API error response mentions "Secret reference is not accessible"
    And no credential provider "tenant-cc" is stored

  Scenario: A tenant credential provider can reference its own tenant's secrets
    Given the operator can use the admin API and no surface is configured for route "/example"
    And tenant "tenant-a" holds the secret "own-id-secret"
    And tenant "tenant-a" holds the secret "own-password-secret"
    When the operator creates the credential provider "tenant-cc" for tenant "tenant-a" using secrets "own-id-secret" and "own-password-secret"
    Then the admin API response status is 201
    And the credential provider "tenant-cc" is stored

  Scenario: Two tenants each create an authorization code provider with the same provider id
    Given the operator can use the admin API and no surface is configured for route "/example"
    And tenant "tenant-a" holds the secret "alpha-id-secret"
    And tenant "tenant-a" holds the secret "alpha-password-secret"
    And tenant "tenant-b" holds the secret "bravo-id-secret"
    And tenant "tenant-b" holds the secret "bravo-password-secret"
    And the operator has created the authorization code provider "example" for tenant "tenant-a" using secrets "alpha-id-secret" and "alpha-password-secret"
    When the operator creates the authorization code provider "example" for tenant "tenant-b" using secrets "bravo-id-secret" and "bravo-password-secret"
    Then the admin API response status is 201
    And both credential providers "example" have a callback path ending in the id the gateway gave each

  Scenario: The surface routing settings name the gateway's own base URL for callback URLs
    Given the operator can use the admin API and no surface is configured for route "/example"
    When the operator reads the surface routing settings
    Then the admin API response status is 200
    And the surface routing settings name the gateway's own https address as its base URL

  Scenario: An authorization code provider cannot be created with a callback URL
    Given the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "provider-id-secret"
    And the appliance holds the secret "provider-password-secret"
    When the operator creates the authorization code provider "example" with callback URL "https://192.0.2.1/v1/identity/oauth/callback/example" using secrets "provider-id-secret" and "provider-password-secret"
    Then the admin API response status is 400
    And the admin API error response mentions "callback_url is set by an update after create"
    And no credential provider "example" is stored

  Scenario: A tenant surface cannot newly authenticate its target with an appliance-wide secret
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target
    And the appliance holds the secret "appliance-key"
    And tenant "tenant-a" holds the secret "tenant-key"
    And the operator has created the surface for route "/tenant-owned" owned by tenant "tenant-a" authenticating its target with secret "tenant-key"
    When the operator saves the surface authenticating its target with secret "appliance-key"
    Then the admin API response status is 400
    And the admin API error response mentions "Secret reference is not accessible"
    And the stored surface authenticates its target with secret "tenant-key"

  Scenario: A surface that holds an appliance-wide secret cannot be reassigned to a tenant
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target
    And the appliance holds the secret "appliance-key"
    And the operator has created the appliance-wide surface for route "/wide" authenticating its target with secret "appliance-key"
    When the operator reassigns the surface to tenant "tenant-a"
    Then the admin API response status is 409
    And the admin API error response mentions "tenant_reassignment_blocked"
    And the admin API error response mentions "The proposed tenant would give a tenant resource an appliance-wide credential"
    And the stored surface belongs to no tenant

  Scenario: A tenant surface that holds its tenant's secret cannot be reassigned to another tenant
    Given the operator can use the admin API and no surface is configured for route "/example"
    And managed agent "bravo" is available as the surface target
    And tenant "tenant-a" holds the secret "tenant-key"
    And the operator has created the surface for route "/tenant-owned" owned by tenant "tenant-a" authenticating its target with secret "tenant-key"
    When the operator reassigns the surface to tenant "tenant-b"
    Then the admin API response status is 409
    And the admin API error response mentions "tenant_reassignment_blocked"
    And the stored surface belongs to tenant "tenant-a"

  Scenario: A tenant surface that already stores an appliance-wide secret can be saved again in warn mode
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "tenant-a"
    And the gateway authenticates to the managed agent with secret "appliance-key" holding "appliance-secret-value" in header "Authorization"
    When the operator saves the surface with the description "Renamed in the dashboard"
    Then the admin API response status is 200
    And the stored surface has the description "Renamed in the dashboard"
    And the stored surface authenticates its target with secret "appliance-key"

  Scenario: A tenant surface that already stores an appliance-wide secret cannot be saved again when tenant isolation is enforced
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "tenant-a"
    And the gateway authenticates to the managed agent with secret "appliance-key" holding "appliance-secret-value" in header "Authorization"
    And the gateway enforces the credential rule "tenant_credential_isolation"
    When the operator saves the surface with the description "Renamed in the dashboard"
    Then the admin API response status is 400
    And the admin API error response mentions "Secret reference is not accessible"
    And the stored surface has the description "BDD test surface"
    And the stored surface authenticates its target with secret "appliance-key"

  Scenario: A surface whose stored Target credential breaks both Target rules saves again unchanged in warn mode
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" is reached over plain http
    And the surface's Access Point does not check its callers
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the gateway only warns on the credential rule "target_https"
    And the gateway only warns on the credential rule "target_source_auth"
    When the operator saves the surface with the description "Renamed in the dashboard"
    Then the admin API response status is 200
    And the stored surface has the description "Renamed in the dashboard"
    And the stored surface authenticates its target with secret "bdd-target-api-key"
    And the admin API response carries a Warning header containing "target.auth sends a credential, so its Target must be an https URL; it will be refused once credential_policy.target_https is enforce"

  Scenario: A surface whose stored Target credential breaks both Target rules saves again unchanged when both are enforced
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" is reached over plain http
    And the surface's Access Point does not check its callers
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the gateway enforces the credential rule "target_https"
    And the gateway enforces the credential rule "target_source_auth"
    When the operator saves the surface with the description "Renamed in the dashboard"
    Then the admin API response status is 200
    And the stored surface has the description "Renamed in the dashboard"
    And the stored surface authenticates its target with secret "bdd-target-api-key"
    And the admin API response carries a Warning header containing "target.auth sends a credential, so its Target must be an https URL; the credential is withheld while credential_policy.target_https is enforce"
    And the admin API response carries a Warning header containing "target.auth sends a credential, so it needs source authentication on the Access Point; the credential is withheld while credential_policy.target_source_auth is enforce"

  Scenario: A surface whose stored Transit Point credential breaks both Target rules saves again unchanged when both are enforced
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"
    And Transit Point "alpha" is an Open Transit Point
    And MCP server "bravo" is reached over plain http
    And the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway enforces the credential rule "target_https"
    And the gateway enforces the credential rule "target_source_auth"
    When the operator saves the surface with the description "Renamed in the dashboard"
    Then the admin API response status is 200
    And the stored surface has the description "Renamed in the dashboard"
    And the admin API response carries a Warning header containing "transit.points['alpha'].target_auth sends a credential, so its target endpoint must be an https URL; the credential is withheld while credential_policy.target_https is enforce"
    And the admin API response carries a Warning header containing "transit.points['alpha'].target_auth sends a credential, so it needs a Transit Point that authenticates its callers; the credential is withheld while credential_policy.target_source_auth is enforce"

  Scenario: Editing a stored Target credential that breaks the https rule is saved with a warning in warn mode
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" is reached over plain http
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    And the gateway keeps its log of warnings
    When the operator saves the surface with its Target authentication formatting the value as "Token {value}"
    Then the admin API response status is 200
    And the gateway log has a warning containing "it will be refused once credential_policy.target_https is enforce"
    And the admin API response carries a Warning header containing "target.auth sends a credential, so its Target must be an https URL; it will be refused once credential_policy.target_https is enforce"

  Scenario: Editing a stored Target credential that breaks the https rule is refused when https Targets are enforced
    Given an A2A surface targeting managed agent "bravo"
    And managed agent "bravo" is reached over plain http
    And the gateway enforces the credential rule "target_https"
    And the gateway authenticates to the managed agent with secret "bdd-target-api-key" holding "bdd-target-secret" in header "x-target-api-key"
    When the operator saves the surface with its Target authentication formatting the value as "Token {value}"
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth sends a credential, so its Target must be an https URL"
    And the stored surface has the description "BDD test surface"

  Scenario: Editing a stored Transit Point credential that breaks the https rule is refused when https Targets are enforced
    Given A2A surface "example-surface" is defined for route "/example" with managed agent "example-agent" as its target
    And Transit Point "alpha" routes to MCP server "bravo"
    And MCP server "bravo" is reached over plain http
    And the gateway authenticates to the destination of Transit Point "alpha" with a client credentials provider
    And the gateway enforces the credential rule "target_https"
    When the operator saves the surface with the Target authentication of Transit Point "alpha" falling back to "passthrough"
    Then the admin API response status is 400
    And the admin API error response mentions "transit.points['alpha'].target_auth sends a credential, so its target endpoint must be an https URL"
