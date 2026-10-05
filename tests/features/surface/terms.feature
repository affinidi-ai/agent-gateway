Feature: Terms consent and management
  Human users accept current Terms before product access, while appliance administrators manage Customer Terms.

  Scenario: Cached Affinidi Terms remain available while Affinidi Well is unavailable
    Given Terms consent is enabled
    And Affinidi Terms version "3.2" was received from Affinidi Well
    And Affinidi Well is unavailable
    When human user "alice" signs in
    Then authentication succeeds
    And a consent-pending session is issued to human user "alice"

  Scenario: An administrator can see degraded Affinidi Terms refresh status
    Given Terms consent is enabled
    And administrator "ada" accepted all applicable Terms
    And Affinidi Well is unavailable
    When administrator "ada" requests the T&C Manager data
    Then the request succeeds
    And the Affinidi Terms provider status is degraded

  Scenario: Human authentication fails until the first Affinidi Terms version is received
    Given Terms consent is enabled
    And Affinidi Well is unavailable before the appliance has received metadata
    When human user "alice" signs in
    Then authentication fails because Terms status is unavailable
    And no authenticated session is issued

  Scenario: Dedicated Terms health reports an unavailable provider without failing readiness
    Given Terms consent is enabled
    And Affinidi Well is unavailable before the appliance has received metadata
    When the caller requests Affinidi Terms provider health
    Then the request succeeds
    And the Affinidi Terms provider health state is unavailable

  Scenario: A new Affinidi Terms version requiring re-consent affects the next login
    Given Terms consent is enabled
    And human user "alice" accepted Affinidi Terms version "3.2"
    And Affinidi Well publishes version "3.3" requiring re-consent
    And the appliance has refreshed Affinidi Terms metadata
    When human user "alice" signs in
    Then authentication succeeds
    And a consent-pending session is issued to human user "alice"

  Scenario: A central update rejects a stale acceptance submission
    Given Terms consent is enabled
    And administrator "ada" has a consent-pending session
    And administrator "ada" loaded the applicable Terms
    And Affinidi Well publishes version "3.3" requiring re-consent
    And the appliance has refreshed Affinidi Terms metadata
    When administrator "ada" submits the previously loaded Terms
    Then the acceptance is rejected as stale
    And the response status is 409

  Scenario: A central Affinidi Terms update does not interrupt an active session
    Given Terms consent is enabled
    And human user "alice" accepted Affinidi Terms version "3.2"
    And Affinidi Well publishes version "3.3" requiring re-consent
    And the appliance has refreshed Affinidi Terms metadata
    When human user "alice" requests a protected product resource with the active session
    Then the request succeeds

  Scenario: Invalid central metadata retains the last-known-good Affinidi Terms
    Given Terms consent is enabled
    And administrator "ada" accepted all applicable Terms
    And Affinidi Well serves an invalid publication
    When administrator "ada" requests the T&C Manager data
    Then the request succeeds
    And the Affinidi Terms provider status is degraded
    And Affinidi Terms version "3.2" remains active

  Scenario: A central rollback retains the last-known-good Affinidi Terms
    Given Terms consent is enabled
    And administrator "ada" accepted all applicable Terms
    And Affinidi Well publishes version "3.3" requiring re-consent
    And the appliance has refreshed Affinidi Terms metadata
    And Affinidi Well serves a rollback publication
    When administrator "ada" requests the T&C Manager data
    Then the request succeeds
    And the Affinidi Terms provider status is degraded
    And Affinidi Terms version "3.3" remains active

  Scenario: A central update leaves accepted Customer Terms independent
    Given Terms consent is enabled
    And human user "alice" accepted Customer Terms version "1"
    And Affinidi Well publishes version "3.3" requiring re-consent
    And the appliance has refreshed Affinidi Terms metadata
    When human user "alice" signs in and requests Terms status
    Then only Affinidi Terms require acceptance

  Scenario: An existing human user without Acceptance Records receives a consent-pending session
    Given Terms consent is enabled
    And Affinidi Terms version "3.2" is current
    When human user "alice" signs in
    Then authentication succeeds
    And a consent-pending session is issued to human user "alice"

  Scenario: A consent-pending session cannot use the Admin API
    Given Terms consent is enabled
    And administrator "ada" has a consent-pending session
    When administrator "ada" requests a protected Admin API resource
    Then the request is rejected because Terms acceptance is required
    And the response status is 403

  Scenario: Acceptance by one session unlocks every pending session for the human user
    Given Terms consent is enabled
    And human user "alice" has two consent-pending sessions
    And one session has accepted all applicable Terms
    When the other session requests a protected product resource
    Then the request succeeds

  Scenario: A replacement requiring re-consent affects the next login
    Given Terms consent is enabled
    And human user "alice" accepted Customer Terms version "1"
    And current Customer Terms version "2" requires re-consent
    When human user "alice" signs in
    Then authentication succeeds
    And a consent-pending session is issued to human user "alice"

  Scenario: Publishing replacement Terms does not interrupt an active session
    Given Terms consent is enabled
    And human user "alice" has an unrestricted session after accepting Customer Terms version "1"
    And current Customer Terms version "2" requires re-consent
    When human user "alice" requests a protected product resource with the active session
    Then the request succeeds

  Scenario: An appliance administrator publishes the Customer Terms draft
    Given Terms consent is enabled
    And administrator "ada" has saved Customer Terms draft version "1" at "https://example.com/terms/1"
    When administrator "ada" publishes the Customer Terms draft
    Then Customer Terms version "1" is published
    And the published Customer Terms have an immutable version ID

  Scenario: A human user without Terms edit permission cannot publish Customer Terms
    Given Terms consent is enabled
    And human user "uma" lacks permission to edit Customer Terms
    And a Customer Terms draft is ready to publish
    When human user "uma" attempts to publish the Customer Terms draft
    Then publication is forbidden
    And the response status is 403

  Scenario: Terms consent does not restrict data-plane callers
    Given Terms consent is enabled
    And an A2A surface targeting managed agent "bravo"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
