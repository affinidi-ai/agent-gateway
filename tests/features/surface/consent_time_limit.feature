Feature: Consent time limit
  A consent to a credential provider can have an end. From then on the gateway
  neither uses nor refreshes the delegated credential: it removes it and asks
  the caller to consent again.

  Background:
    Given MCP surface "alpha" targets MCP server "bravo"
    And MCP server "bravo" supports tool invocation
    And the surface requires "JWT Bearer" source authentication
    And the VP Audit Log keeps every audit event
    And the surface requires delegated credentials from OAuth provider "calendar"

  Scenario: A consent within its time limit is used
    Given OAuth provider "calendar" limits a consent to 3600 seconds
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received delegated credential for OAuth provider "calendar"

  Scenario: A consent given under a time limit is stored with its end
    Given OAuth provider "calendar" limits a consent to 3600 seconds
    And caller "alice" has started OAuth consent for provider "calendar"
    And OAuth provider "calendar" is ready to exchange an authorization code for delegated credentials
    When OAuth provider "calendar" redirects the caller back with a valid authorization code
    Then the OAuth callback response status is 200
    And the delegated credential in the delegation vault ends its consent 3600 seconds after it was given

  Scenario: A consent given under a time limit is audited with its end
    Given OAuth provider "calendar" limits a consent to 3600 seconds
    And caller "alice" has started OAuth consent for provider "calendar"
    And OAuth provider "calendar" is ready to exchange an authorization code for delegated credentials
    When OAuth provider "calendar" redirects the caller back with a valid authorization code
    Then the OAuth callback response status is 200
    And the delegation audit trail records when the consent to OAuth provider "calendar" ends

  Scenario: A caller asked for consent is told how long it will last
    Given OAuth provider "calendar" limits a consent to 3600 seconds
    And caller "alice" has no delegated credentials for OAuth provider "calendar"
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 401
    And the response is a consent required error for OAuth provider "calendar"
    And the consent required error says a new consent to OAuth provider "calendar" may be used for 3600 seconds
    And the consent required error for OAuth provider "calendar" gives no reason

  Scenario: A consent past its time limit is removed and the caller is asked to consent again
    Given OAuth provider "calendar" limits a consent to 3600 seconds
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the caller's consent was given 7200 seconds ago
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 401
    And the response is a consent required error for OAuth provider "calendar"
    And the consent required error for OAuth provider "calendar" gives the reason "consent_expired"
    And the delegation audit trail contains event "consent_expired" for OAuth provider "calendar"
    And the delegation vault holds no delegated credential
    And MCP server "bravo" was not called

  Scenario: A consent past its time limit is not refreshed
    Given OAuth provider "calendar" limits a consent to 3600 seconds
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the caller's consent was given 7200 seconds ago
    And the caller's delegated credentials have expired
    And OAuth provider "calendar" is ready to refresh delegated credentials
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 401
    And the consent required error for OAuth provider "calendar" gives the reason "consent_expired"
    And OAuth provider "calendar" was not asked to refresh delegated credentials
    And MCP server "bravo" was not called

  Scenario Outline: The operator is told how many active consents a time limit would end before saving it
    Given OAuth provider "calendar" limits a consent to 21600 seconds
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the caller's consent was given 7200 seconds ago
    When the operator asks what a consent time limit of <limit> seconds on OAuth provider "calendar" would end
    Then the admin API response status is 200
    And the gateway counts 1 active consent, of which the limit would end <ended>
    And the delegation vault holds 1 delegated credential

    Examples:
      | limit | ended |
      | 3600  | 1     |
      | 14400 | 0     |

  Scenario: A consent time limit outside the range is refused before it is counted
    When the operator asks what a consent time limit of 30 seconds on OAuth provider "calendar" would end
    Then the admin API response status is 400

  Scenario: An operator limits one consent, which then ends sooner
    Given OAuth provider "calendar" limits a consent to 21600 seconds
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the caller's consent was given 3600 seconds ago
    When the operator limits the caller's consent to 7200 seconds
    Then the admin API response status is 200
    And the delegated credential in the delegation vault ends its consent 7200 seconds after it was given
    And the delegation audit trail contains event "consent_limited" for OAuth provider "calendar"

  Scenario: A consent an operator limited is removed at its new end
    Given OAuth provider "calendar" limits a consent to 21600 seconds
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the operator has limited the caller's consent to 7200 seconds
    And the caller's consent was given 7300 seconds ago
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 401
    And the consent required error for OAuth provider "calendar" gives the reason "consent_expired"
    And the delegation vault holds no delegated credential
    And MCP server "bravo" was not called

  Scenario Outline: A limit that would extend one consent, or end it at once, is refused
    Given OAuth provider "calendar" limits a consent to 21600 seconds
    And caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the caller's consent was given 3600 seconds ago
    When the operator limits the caller's consent to <limit> seconds
    Then the admin API response status is 400
    And the delegated credential in the delegation vault ends its consent 21600 seconds after it was given

    Examples:
      | limit |
      | 43200 |
      | 1800  |

  Scenario: Without a time limit a consent is used however old
    Given caller "alice" has started OAuth consent for provider "calendar"
    And caller "alice" has completed OAuth consent for provider "calendar"
    And the caller's consent was given 34560000 seconds ago
    When caller "alice" invokes MCP tool "schedule_meeting" with a valid token
    Then the response status is 200
    And MCP server "bravo" received delegated credential for OAuth provider "calendar"
