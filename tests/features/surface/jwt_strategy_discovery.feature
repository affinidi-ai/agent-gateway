Feature: JWT verification strategy authorization server discovery
  An operator gives a JWT verification strategy only the issuer of an
  authorization server. The gateway reads the authorization server's metadata
  (RFC 8414, then OpenID Connect Discovery) and can pin its issuer, the document
  it read, its token endpoint and its key set URI on the strategy. It accepts a
  document only when the document's issuer equals the strategy's issuer exactly.
  A failed discovery is refused with a fixed code and never reveals where the
  gateway connected or why the connection failed. The pin never outlives its
  issuer, and token verification keeps using the strategy's own key set.

  Scenario Outline: Discovery shows the metadata a save would pin and stores nothing
    Given authorization server "alpha" <publication>
    When the operator discovers the metadata of authorization server "alpha"
    Then the admin API response status is 200
    And the discovered metadata matches the published metadata of authorization server "alpha"
    And no JWT verification strategy is stored for authorization server "alpha"

    Examples:
      | publication                                   |
      | publishes OAuth authorization server metadata |
      | publishes an OpenID Connect configuration     |

  Scenario: Discovery refuses a document that names another issuer
    Given authorization server "alpha" publishes metadata naming another issuer
    When the operator discovers the metadata of authorization server "alpha"
    Then the admin API response status is 422
    And the admin API error code is "issuer_mismatch"
    And the admin API error does not reveal the address of authorization server "alpha"
    And no JWT verification strategy is stored for authorization server "alpha"

  Scenario: A save with discovery pins the authorization server
    Given authorization server "alpha" publishes OAuth authorization server metadata
    When the operator creates JWT verification strategy "workforce" for authorization server "alpha" with discovery
    Then the admin API response status is 201
    And JWT verification strategy "workforce" pins the published metadata of authorization server "alpha"
    And JWT verification strategy "workforce" reads its keys from its own key set

  Scenario Outline: A save whose discovery fails is refused and stores nothing
    Given authorization server "alpha" <publication>
    When the operator creates JWT verification strategy "workforce" for authorization server "alpha" with discovery
    Then the admin API response status is 422
    And the admin API error code is "<code>"
    And the admin API error does not reveal the address of authorization server "alpha"
    And JWT verification strategy "workforce" is not stored

    Examples:
      | publication                                     | code             |
      | does not publish metadata                       | http_status      |
      | publishes metadata naming another issuer        | issuer_mismatch  |
      | publishes an oversized metadata document        | too_large        |
      | publishes a metadata document without a key set | invalid_document |

  Scenario Outline: A strategy without one concrete issuer is refused
    When the operator creates JWT verification strategy "workforce" with issuer "<issuer>" and discovery
    Then the admin API response status is 400
    And the admin API error response mentions "<reason>"
    And JWT verification strategy "workforce" is not stored

    Examples:
      | issuer                                | reason            |
      |                                       | must not be empty |
      | https://login.example/{tenantid}/v2.0 | not a template    |

  Scenario: A save with discovery turned off clears the pin
    Given authorization server "alpha" publishes OAuth authorization server metadata
    And JWT verification strategy "workforce" is pinned to authorization server "alpha"
    When the operator saves JWT verification strategy "workforce" with discovery turned off
    Then the admin API response status is 200
    And JWT verification strategy "workforce" has no pinned authorization server
    And JWT verification strategy "workforce" expects the issuer of authorization server "alpha"

  Scenario: Moving the issuer pins the new authorization server
    Given authorization server "alpha" publishes OAuth authorization server metadata
    And JWT verification strategy "workforce" is pinned to authorization server "alpha"
    And authorization server "bravo" publishes an OpenID Connect configuration
    When the operator moves JWT verification strategy "workforce" to the issuer of authorization server "bravo"
    Then the admin API response status is 200
    And JWT verification strategy "workforce" pins the published metadata of authorization server "bravo"

  Scenario: Moving the issuer to an authorization server that cannot be discovered clears the pin
    Given authorization server "alpha" publishes OAuth authorization server metadata
    And JWT verification strategy "workforce" is pinned to authorization server "alpha"
    And authorization server "bravo" does not publish metadata
    When the operator moves JWT verification strategy "workforce" to the issuer of authorization server "bravo"
    Then the admin API response status is 200
    And JWT verification strategy "workforce" expects the issuer of authorization server "bravo"
    And JWT verification strategy "workforce" has no pinned authorization server

  Scenario: A pinned strategy verifies callers with its own key set
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface has a policy denying callers whose source authentication failed
    And authorization server "alpha" publishes OAuth authorization server metadata
    And the surface's JWT verification strategy trusts authorization server "alpha" and pins its metadata
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the forwarded request
    And authorization server "alpha" received no request for its key set

  Scenario: A client without a session cannot make the gateway call an authorization server
    Given authorization server "alpha" publishes OAuth authorization server metadata
    When a client without a session asks to discover the metadata of authorization server "alpha"
    Then the admin API response status is 401
    And authorization server "alpha" received no request

  Scenario: An operator who cannot edit strategies cannot make the gateway call an authorization server
    Given authorization server "alpha" publishes OAuth authorization server metadata
    And operator "uma" has the "user" role
    When operator "uma" discovers the metadata of authorization server "alpha"
    Then the admin API response status is 403
    And authorization server "alpha" received no request
