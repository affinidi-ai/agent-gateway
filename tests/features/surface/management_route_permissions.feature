Feature: Management route permissions
  Removing rotated log files and truncating stored metrics need settings.edit. Reading or
  changing the user welcome template and sending a welcome notification need users.approve.
  Both permissions belong to administrators by default. A personal access token with feature
  scopes also needs the permission among its scopes. Downloading the server logs needs
  audit.view, and since the logs hold every tenant's request and delegation detail, a tenant's
  access token or one scoped by required headers alone cannot download them and is shown none
  of their lines on the dashboard. Listing and reading agents needs surfaces.view, and a tenant's
  token sees only the agents of its own surfaces. A tenant's token reads an agent card only
  through a surface of its own tenant. A personal access token with feature scopes reaches a
  route only when one of its scopes covers it, including a route a signed-in operator reaches
  without any permission: reading the gateway settings needs settings.view. Whatever its scopes,
  such a token reads its own token info and never reads the operator profile.

  Scenario: An administrator downloads the server logs
    Given a log file "agent-gateway.log"
    And operator "ada" has the "administrator" role
    When operator "ada" downloads the server logs
    Then the admin API response status is 200
    And the answer is a ZIP archive of the server logs

  Scenario: A tenant token cannot download the server logs
    Given a log file "agent-gateway.log"
    When a token of tenant "tenant-a" downloads the server logs
    Then the admin API response status is 403

  Scenario: An access token scoped by required headers alone cannot download the server logs
    Given a log file "agent-gateway.log"
    When an access token scoped by required headers alone downloads the server logs
    Then the admin API response status is 403

  Scenario: An appliance-wide access token reads the gateway's log lines on the dashboard
    Given a log file "agent-gateway.log"
    And the gateway log holds the line "request served for tenant-b"
    When an appliance-wide access token reads the dashboard's log lines
    Then the admin API response status is 200
    And the answer holds the log line "request served for tenant-b"

  Scenario: A tenant token is shown none of the gateway's log lines on the dashboard
    Given a log file "agent-gateway.log"
    And the gateway log holds the line "request served for tenant-b"
    When a token of tenant "tenant-a" reads the dashboard's log lines
    Then the admin API response status is 200
    And the answer holds no log lines

  Scenario: An access token scoped by required headers alone is shown none of the gateway's log lines
    Given a log file "agent-gateway.log"
    And the gateway log holds the line "request served for tenant-b"
    When an access token scoped by required headers alone reads the dashboard's log lines
    Then the admin API response status is 200
    And the answer holds no log lines

  Scenario: A base user cannot remove rotated log files
    Given a log file "agent-gateway.log.1"
    And operator "uma" has the "user" role
    When operator "uma" removes old log files
    Then the admin API response status is 403
    And the log file "agent-gateway.log.1" still exists

  Scenario: An administrator removes rotated log files
    Given a log file "agent-gateway.log"
    And a log file "agent-gateway.log.1"
    And operator "ada" has the "administrator" role
    When operator "ada" removes old log files
    Then the admin API response status is 200
    And the response reports 1 removed log file
    And the log file "agent-gateway.log.1" is gone
    And the log file "agent-gateway.log" still exists

  Scenario: A personal access token without settings.edit cannot remove rotated log files
    Given a log file "agent-gateway.log.1"
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view"
    When the personal access token removes old log files
    Then the admin API response status is 403
    And the log file "agent-gateway.log.1" still exists

  Scenario: A personal access token with settings.edit removes rotated log files
    Given a log file "agent-gateway.log.1"
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "settings.edit"
    When the personal access token removes old log files
    Then the admin API response status is 200
    And the response reports 1 removed log file
    And the log file "agent-gateway.log.1" is gone

  Scenario: A base user cannot truncate stored metrics
    Given operator "uma" has the "user" role
    When operator "uma" truncates stored metrics
    Then the admin API response status is 403

  Scenario: A personal access token without settings.edit cannot truncate stored metrics
    Given operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view"
    When the personal access token truncates stored metrics
    Then the admin API response status is 403

  Scenario: An administrator truncates stored metrics
    Given operator "ada" has the "administrator" role
    When operator "ada" truncates stored metrics
    Then the admin API response status is 200
    And the response reports the removed and retained metrics records

  Scenario: A base user cannot read the user welcome template
    Given operator "uma" has the "user" role
    When operator "uma" reads the user welcome template
    Then the admin API response status is 403

  Scenario: A personal access token without users.approve cannot read the user welcome template
    Given operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view"
    When the personal access token reads the user welcome template
    Then the admin API response status is 403

  Scenario: A power user cannot change the user welcome template
    Given operator "pete" has the "poweruser" role
    And operator "ada" has the "administrator" role
    When operator "pete" changes the user welcome template title to "Probe"
    Then the admin API response status is 403
    And operator "ada" reads a user welcome template not titled "Probe"

  Scenario: A personal access token without users.approve cannot change the user welcome template
    Given operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view"
    When the personal access token changes the user welcome template title to "Probe"
    Then the admin API response status is 403
    And operator "ada" reads a user welcome template not titled "Probe"

  Scenario: An administrator changes the user welcome template
    Given operator "ada" has the "administrator" role
    When operator "ada" changes the user welcome template title to "Welcome to the gateway"
    Then the admin API response status is 204
    And operator "ada" reads a user welcome template titled "Welcome to the gateway"

  Scenario: A base user cannot send a welcome notification
    Given operator "uma" has the "user" role
    And operator "ada" has the "administrator" role
    When operator "uma" sends a welcome notification titled "Probe" to operator "ada"
    Then the admin API response status is 403
    And operator "ada" has no notification titled "Probe"

  Scenario: A personal access token without users.approve cannot send a welcome notification
    Given operator "uma" has the "user" role
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view"
    When the personal access token sends a welcome notification titled "Probe" to operator "uma"
    Then the admin API response status is 403
    And operator "uma" has no notification titled "Probe"

  Scenario: An administrator sends a welcome notification
    Given operator "uma" has the "user" role
    And operator "ada" has the "administrator" role
    When operator "ada" sends a welcome notification titled "Welcome aboard" to operator "uma"
    Then the admin API response status is 204
    And operator "uma" has a notification titled "Welcome aboard"

  Scenario: A personal access token without surfaces.view cannot list the agents
    Given operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "settings.edit"
    When the personal access token lists the agents
    Then the admin API response status is 403

  Scenario: A personal access token with surfaces.view lists the agents
    Given an A2A surface targeting managed agent "bravo"
    And operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view"
    When the personal access token lists the agents
    Then the admin API response status is 200
    And the agents list names the surface

  Scenario: A token of the surface's tenant lists its agent
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "tenant-a"
    And a personal access token of tenant "tenant-a"
    When the personal access token lists the agents
    Then the admin API response status is 200
    And the agents list names the surface

  Scenario: A token of the surface's tenant reads its agent
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "tenant-a"
    And the operator has looked up the surface's agent
    And a personal access token of tenant "tenant-a"
    When the personal access token reads the surface's agent
    Then the admin API response status is 200
    And the agent answer names the surface

  Scenario: A token of another tenant does not list the surface's agent
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "tenant-a"
    And a personal access token of tenant "tenant-b"
    When the personal access token lists the agents
    Then the admin API response status is 200
    And the agents list is empty

  Scenario: A token of another tenant cannot read the surface's agent
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "tenant-a"
    And the operator has looked up the surface's agent
    And a personal access token of tenant "tenant-b"
    When the personal access token reads the surface's agent
    Then the admin API response status is 404

  Scenario: A token limited to another surface of its tenant cannot read the surface's agent
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "tenant-a"
    And the operator has looked up the surface's agent
    And a personal access token of tenant "tenant-a" limited to surface "other-surface"
    When the personal access token reads the surface's agent
    Then the admin API response status is 404

  Scenario: A token of another tenant cannot read the agent card of the surface's agent
    Given an A2A surface targeting managed agent "bravo"
    And the surface belongs to tenant "tenant-a"
    And the operator has looked up the surface's agent
    And a personal access token of tenant "tenant-b"
    When the personal access token reads the agent card of the surface's agent
    Then the admin API response status is 404

  Scenario: A tenant token reads no agent card through an appliance-wide surface
    Given an A2A surface targeting managed agent "bravo"
    And the operator has looked up the surface's agent
    And a personal access token of tenant "tenant-a"
    When the personal access token reads the agent card of the surface's agent
    Then the admin API response status is 200
    And the agent card is unavailable because only an operator may read it

  Scenario: A base user cannot validate a credential provider
    Given operator "uma" has the "user" role
    When operator "uma" validates a credential provider
    Then the admin API response status is 403

  Scenario: An administrator validates a credential provider
    Given operator "ada" has the "administrator" role
    When operator "ada" validates a credential provider
    Then the admin API response status is 200
    And the response reports the token endpoint the credential provider validation checked

  Scenario: A personal access token whose scopes do not cover the gateway settings cannot read them
    Given operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view"
    When the personal access token reads the gateway settings
    Then the admin API response status is 403

  Scenario: A personal access token with settings.view reads the gateway settings
    Given operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "settings.view"
    When the personal access token reads the gateway settings
    Then the admin API response status is 200

  Scenario: A personal access token reads its own token info whatever its scopes
    Given operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "surfaces.view"
    When the personal access token reads its own token info
    Then the admin API response status is 200
    And the token info lists the scopes "surfaces.view"

  Scenario: A personal access token cannot read the operator profile whatever its scopes
    Given operator "ada" has the "administrator" role
    And operator "ada" holds a personal access token with scopes "settings.view, users.view, surfaces.view"
    When the personal access token reads the operator profile
    Then the admin API response status is 403
