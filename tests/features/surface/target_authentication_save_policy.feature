Feature: Credential policy rules when saving Target authentication
  A new or changed Target authentication that sends its credential to a Target that is not
  https, or from a leg that does not check who calls it, is saved with a warning while the
  matching credential policy rule is in warn, and refused naming the field once the rule is
  enforced. A Target credential the operator leaves unchanged is checked again when another
  edit, such as removing the Access Point's caller check or moving the Target to http, makes it
  break a rule. A closed Access Point with no Caller Context saves as not ready, except that a
  Target credential on it is refused while Target source authentication is enforced. A Transit
  Point checks its callers when it requires a transit token, checks their MCP authorization, or
  has its own source authentication.

  Scenario: A Target credential for a plain http Target is saved with a warning in warn mode
    Given the gateway keeps its log of warnings
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/warned" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft's Target is "http://127.0.0.1:9/"
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the gateway log has a warning containing "target.auth sends a credential, so its Target must be an https URL; it will be refused once credential_policy.target_https is enforce"
    And the admin API response carries a Warning header containing "target.auth sends a credential, so its Target must be an https URL; it will be refused once credential_policy.target_https is enforce"

  Scenario: A Target credential for a plain http Target is refused when https Targets are enforced
    Given the gateway enforces the credential rule "target_https"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft's Target is "http://127.0.0.1:9/"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth sends a credential, so its Target must be an https URL"

  Scenario Outline: A header rule is enforced while the Target credential rules only warn
    Given the gateway only warns on the credential rule "target_https"
    And the gateway only warns on the credential rule "target_source_auth"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/refused" whose Target receives secret "target-key" in header "<header>"
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft's Target is "http://127.0.0.1:9/"
    And the draft's Target authentication formats its value as "<format>"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "<message>"

    Examples:
      | header       | format  | message                                                      |
      | Host         | {value} | target.auth.header_name must not be the reserved header Host |
      | X-Target-Key | Bearer  | target.auth.header_format must contain {value} exactly once |

  Scenario: A Target credential on a closed Access Point without a Caller Context is saved not ready with a warning in warn mode
    Given the gateway keeps its log of warnings
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/warned" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point is closed
    And the draft's Access Point does not check its callers
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the gateway log has a warning containing "it will be refused once credential_policy.target_source_auth is enforce"
    And the admin API response carries a Warning header containing "target.auth sends a credential, so it needs source authentication on the Access Point; it will be refused once credential_policy.target_source_auth is enforce"
    And the admin API response carries a Warning header containing "This Access Point is not ready for external access"

  Scenario: A Target credential on a closed Access Point without a Caller Context is refused when Target source authentication is enforced
    Given the gateway enforces the credential rule "target_source_auth"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point is closed
    And the draft's Access Point does not check its callers
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth sends a credential, so it needs source authentication on the Access Point"

  Scenario: Removing the caller check under a stored Target credential is saved with a warning in warn mode
    Given the gateway only warns on the credential rule "target_source_auth"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/stored" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the operator has created the surface from the draft
    When the operator saves the surface without its Access Point's caller check
    Then the admin API response status is 200
    And the admin API response carries a Warning header containing "target.auth sends a credential, so it needs source authentication on the Access Point; it will be refused once credential_policy.target_source_auth is enforce"

  Scenario: Removing the caller check under a stored Target credential is refused when Target source authentication is enforced
    Given the gateway enforces the credential rule "target_source_auth"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/stored" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the operator has created the surface from the draft
    When the operator saves the surface without its Access Point's caller check
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth sends a credential, so it needs source authentication on the Access Point"

  Scenario: Moving the Target of a stored Target credential to plain http is saved with a warning in warn mode
    Given the gateway only warns on the credential rule "target_https"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/stored" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the operator has created the surface from the draft
    When the operator saves the surface with its Target moved to "http://127.0.0.1:9/"
    Then the admin API response status is 200
    And the admin API response carries a Warning header containing "target.auth sends a credential, so its Target must be an https URL; it will be refused once credential_policy.target_https is enforce"

  Scenario: Moving the Target of a stored Target credential to plain http is refused when https Targets are enforced
    Given the gateway enforces the credential rule "target_https"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/stored" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the operator has created the surface from the draft
    When the operator saves the surface with its Target moved to "http://127.0.0.1:9/"
    Then the admin API response status is 400
    And the admin API error response mentions "target.auth sends a credential, so its Target must be an https URL"

  Scenario: A Transit Point that does not check its callers saves its Target credential with a warning in warn mode
    Given the gateway keeps its log of warnings
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/warned" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    And Transit Point "partner" in the draft is an Open Transit Point
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the gateway log has a warning containing "transit.points['partner'].target_auth sends a credential, so it needs a Transit Point that authenticates its callers"
    And the admin API response carries a Warning header containing "transit.points['partner'].target_auth sends a credential, so it needs a Transit Point that authenticates its callers; it will be refused once credential_policy.target_source_auth is enforce"

  Scenario: A Transit Point that does not check its callers cannot send a Target credential when Target source authentication is enforced
    Given the gateway enforces the credential rule "target_source_auth"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    And Transit Point "partner" in the draft is an Open Transit Point
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "transit.points['partner'].target_auth sends a credential, so it needs a Transit Point that authenticates its callers"

  Scenario: A Transit Point sends its Target credential to a plain http target endpoint with a warning in warn mode
    Given the gateway keeps its log of warnings
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/warned" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the target endpoint of Transit Point "partner" in the draft is "http://127.0.0.1:9/"
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the gateway log has a warning containing "transit.points['partner'].target_auth sends a credential, so its target endpoint must be an https URL"
    And the admin API response carries a Warning header containing "transit.points['partner'].target_auth sends a credential, so its target endpoint must be an https URL; it will be refused once credential_policy.target_https is enforce"

  Scenario: A Transit Point cannot send a Target credential to a plain http target endpoint when https Targets are enforced
    Given the gateway enforces the credential rule "target_https"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/refused" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the target endpoint of Transit Point "partner" in the draft is "http://127.0.0.1:9/"
    When the operator creates the surface from the draft
    Then the admin API response status is 400
    And the admin API error response mentions "transit.points['partner'].target_auth sends a credential, so its target endpoint must be an https URL"

  Scenario: An https Target credential on an Access Point that checks its callers is saved when both Target rules are enforced
    Given the gateway enforces the credential rule "target_https"
    And the gateway enforces the credential rule "target_source_auth"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the admin API response carries no Warning header containing "credential_policy.target_"

  Scenario: A Transit Point that requires a transit token saves its https target endpoint credential when both Target rules are enforced
    Given the gateway enforces the credential rule "target_https"
    And the gateway enforces the credential rule "target_source_auth"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft requires a transit token
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the admin API response carries no Warning header containing "credential_policy.target_"

  Scenario: A Transit Point that checks callers' MCP authorization saves its https target endpoint credential when both Target rules are enforced
    Given the gateway enforces the credential rule "target_https"
    And the gateway enforces the credential rule "target_source_auth"
    And the gateway publishes its Transit Point listener at an https address
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft is an MCP Transit Point that checks callers' MCP authorization
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the admin API response carries no Warning header containing "credential_policy.target_"

  Scenario: A Transit Point with its own source authentication saves its https target endpoint credential when both Target rules are enforced
    Given the gateway enforces the credential rule "target_https"
    And the gateway enforces the credential rule "target_source_auth"
    And the operator can use the admin API and no surface is configured for route "/example"
    And the appliance holds the secret "target-key"
    And the appliance holds the secret "agent-key"
    And a surface draft for route "/checked" whose Target receives secret "target-key" in header "X-Target-Key"
    And the draft's Target is an https URL
    And the draft's Access Point checks callers by the API key in secret "target-key"
    And the draft has Transit Point "partner" that sends secret "target-key" in header "X-Partner-Key"
    And Transit Point "partner" in the draft checks callers by the API key in secret "agent-key"
    And the target endpoint of Transit Point "partner" in the draft is an https URL
    When the operator creates the surface from the draft
    Then the admin API response status is 201
    And the admin API response carries no Warning header containing "credential_policy.target_"
