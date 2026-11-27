Feature: OpenID Connect sign-in
  In OIDC mode human users sign in to the dashboard at one OpenID provider. The gateway verifies
  the ID token the provider issues, admits only accounts that meet the tenant binding of oidc.json
  (unless it sets allow_any_account), and gives each account the role its role claim maps to, set
  again at every sign-in. An account becomes a human user at its first sign-in, approved and never
  the primary administrator, within the appliance's user limit. A refused sign-in hands the
  dashboard no session and stores no user. Deleting such a user keeps a disabled record under the
  provider account, so the account stays refused until an administrator approves it again. An
  oidc.json that writes the client secret into the file, misspells a setting or has no tenant
  binding stops startup.

  Background:
    Given human users sign in with OpenID Connect

  Scenario: The dashboard learns that human users sign in with the provider named on the button
    When the dashboard asks how human users sign in
    Then human users sign in with "oidc" under the label "Example Directory"

  Scenario: A person whose role is mapped signs in and becomes a human user with that role
    When "mallory" signs in with OpenID Connect carrying the roles "gw-power"
    Then the response status is 200
    And the dashboard is handed a session
    And the session "mallory" was handed signs them in with the role "poweruser"

  Scenario: A role removed at the provider is removed at the next sign-in
    Given "mallory" has signed in with OpenID Connect carrying the roles "gw-admins"
    When "mallory" signs in with OpenID Connect carrying the roles "gw-all"
    Then the response status is 200
    And the session "mallory" was handed signs them in with the role "user"
    And human user "mallory" is stored once

  Scenario: An account outside the tenant binding is refused
    When "mallory" signs in with OpenID Connect from the organisation "org-other" carrying the roles "gw-admins"
    Then the response status is 403
    And the dashboard is handed no session
    And no human user is stored

  Scenario: An account whose role value has no mapping is refused, even one named like a gateway role
    When "mallory" signs in with OpenID Connect carrying the roles "administrator"
    Then the response status is 403
    And the dashboard is handed no session
    And no human user is stored

  Scenario: A sign-in finished in a browser that did not start it is refused
    When "mallory" finishes an OpenID Connect sign-in in a browser that did not start it
    Then the response status is 400
    And the dashboard is handed no session
    And no human user is stored

  Scenario: A new account past the appliance's user limit is refused with a page naming the limit
    Given the appliance allows 1 human user
    And "mallory" has signed in with OpenID Connect carrying the roles "gw-all"
    When "trent" signs in with OpenID Connect carrying the roles "gw-all"
    Then the response status is 403
    And the sign-in page says "Appliance limit reached for 'users'"
    And the dashboard is handed no session
    And human user "trent" is not stored

  Scenario: A deleted user is refused at their next OpenID Connect sign-in and not created again
    Given "trent" has signed in with OpenID Connect carrying the roles "gw-admins"
    And "mallory" has signed in with OpenID Connect carrying the roles "gw-power"
    And "trent" has deleted human user "mallory"
    When "mallory" signs in with OpenID Connect carrying the roles "gw-power"
    Then the response status is 403
    And the dashboard is handed no session
    And the OpenID Connect account "mallory" has one stored human user, who is "disabled"

  Scenario: Deleting a user who signs in with OpenID Connect answers that the record was kept disabled
    Given "trent" has signed in with OpenID Connect carrying the roles "gw-admins"
    And "mallory" has signed in with OpenID Connect carrying the roles "gw-all"
    When "trent" deletes human user "mallory"
    Then the response status is 200
    And the delete answers the outcome "disabled"

  Scenario: A deleted user approved again signs in as the same user with the role the provider maps
    Given "trent" has signed in with OpenID Connect carrying the roles "gw-admins"
    And "mallory" has signed in with OpenID Connect carrying the roles "gw-all"
    And "trent" has deleted human user "mallory"
    And "trent" has approved human user "mallory" again
    When "mallory" signs in with OpenID Connect carrying the roles "gw-power"
    Then the response status is 200
    And the session "mallory" was handed signs them in with the role "poweruser"
    And the OpenID Connect account "mallory" has one stored human user, who is "approved"

  Scenario: An OIDC sign-in raises a sign-in event that names its method
    Given an integration whose event set holds the sign-in events
    When "mallory" signs in with OpenID Connect carrying the roles "gw-all"
    Then the response status is 200
    And the integration receives a "user.login" event with login method "oidc"

  Scenario: An OIDC sign-in refused for its role raises a failed sign-in that names no user
    Given an integration whose event set holds the sign-in events
    When "mallory" signs in with OpenID Connect carrying the roles "contractors"
    Then the response status is 403
    And the integration receives a "user.login_failed" event with login method "oidc" and failure reason "role_not_mapped"
    And that event does not contain "mallory"

  Scenario: An OIDC sign-in outside the tenant binding raises a failed sign-in that names no user
    Given an integration whose event set holds the sign-in events
    When "mallory" signs in with OpenID Connect from the organisation "org-other" carrying the roles "gw-admins"
    Then the response status is 403
    And the integration receives a "user.login_failed" event with login method "oidc" and failure reason "claim_not_allowed"
    And that event does not contain "mallory"

  Scenario: An oidc.json that writes the client secret into the file stops the gateway at startup
    Given oidc.json sets "client_secret" to "string://bdd-secret-in-the-file"
    When the gateway tries to start
    Then the gateway refuses to start, naming "client_secret"
    And the gateway log does not contain "bdd-secret-in-the-file"

  Scenario: An oidc.json with a misspelt setting stops the gateway at startup
    Given oidc.json sets "required_claimz" to true
    When the gateway tries to start
    Then the gateway refuses to start, naming "unknown field `required_claimz`"

  Scenario: An oidc.json with no tenant binding stops the gateway at startup
    Given oidc.json has no tenant binding
    When the gateway tries to start
    Then the gateway refuses to start, naming "allow_any_account"
