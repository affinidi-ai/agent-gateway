Feature: Dashboard session lifetime
  A dashboard session ends session_timeout_minutes after its last use, and never later than
  session_max_lifetime_minutes after sign-in (default 720, twelve hours), however active it stays,
  whichever way the person signed in. The session cookie a sign-in sets lasts no longer than that
  lifetime. A lifetime of 0, or of more than 1440 minutes, stops the gateway at startup.

  Scenario: The session cookie of a sign-in lasts no longer than a shorter session lifetime
    Given human users sign in with OpenID Connect
    And config.toml sets the dashboard session lifetime to 5 minutes
    When "mallory" signs in with OpenID Connect carrying the roles "gw-all"
    Then the dashboard is handed a session
    And the session cookie the dashboard is handed lasts 300 seconds

  Scenario Outline: A dashboard session lifetime of <minutes> minutes stops the gateway at startup
    Given config.toml sets the dashboard session lifetime to <minutes> minutes
    When the gateway tries to start
    Then the gateway refuses to start, naming "session_max_lifetime_minutes must be between 1 and 1440, got <minutes>"

    Examples:
      | minutes |
      | 0       |
      | 1441    |
