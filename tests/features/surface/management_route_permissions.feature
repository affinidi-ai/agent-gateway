Feature: Management route permissions
  Removing rotated log files and truncating stored metrics need settings.edit. Reading or
  changing the user welcome template and sending a welcome notification need users.approve.
  Both permissions belong to administrators by default. A personal access token with feature
  scopes also needs the permission among its scopes. Downloading the server logs needs
  audit.view, and since the logs hold every tenant's request and delegation detail, a tenant's
  access token or one scoped by required headers alone cannot download them.

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

  Scenario: A base user cannot validate a credential provider
    Given operator "uma" has the "user" role
    When operator "uma" validates a credential provider
    Then the admin API response status is 403

  Scenario: An administrator validates a credential provider
    Given operator "ada" has the "administrator" role
    When operator "ada" validates a credential provider
    Then the admin API response status is 200
    And the response reports the token endpoint the credential provider validation checked
