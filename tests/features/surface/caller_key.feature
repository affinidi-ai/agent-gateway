Feature: Caller keys
  A surface with a caller key sends its Target a key for each caller whose JWT
  the gateway verified on that request. The gateway derives it from a secret in
  its secrets store, the surface, and the caller's issuer and identity claim, so
  the key is the same on every request from that caller and the Target's own
  operator cannot derive it. No other caller gets a key, and no header of the
  caller key family (x-caller-key, or a name starting x-caller-key-, in any
  case and with _ for -) that a caller sends is forwarded, whether or not the
  surface sets a caller key.

  Scenario: A JWT caller's key reaches the Target the same on every request
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives caller keys from secret "caller-keys"
    And the caller has sent a request to the surface with a valid token
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the caller key of "test-user" in header "x-caller-key" on every request

  Scenario: The Target receives the caller key in the header the surface names
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives caller keys in header "x-caller-key-memory" from secret "caller-keys"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the caller key of "test-user" in header "x-caller-key-memory" on every request
    And managed agent "bravo" did not receive header "x-caller-key"

  Scenario Outline: A caller key the caller sends is replaced by the caller's own key
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives caller keys from secret "caller-keys"
    When the caller sends a request to the surface with a valid token and header "<header>" set to "forged"
    Then the response status is 200
    And managed agent "bravo" received the caller key of "test-user" in header "x-caller-key" on every request
    And managed agent "bravo" received no header with value "forged"

    Examples:
      | header              |
      | x-caller-key        |
      | x_caller_key        |
      | x-caller-key-memory |

  Scenario Outline: A surface without a caller key does not forward one the caller sends
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    When the caller sends a request to the surface with a valid token and header "<header>" set to "forged"
    Then the response status is 200
    And managed agent "bravo" did not receive header "<header>"

    Examples:
      | header              |
      | x-caller-key        |
      | x_caller_key        |
      | x-caller-key-memory |
      | X_Caller_Key_Vault  |

  Scenario Outline: A header outside the caller key family still reaches the Target
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives caller keys from secret "caller-keys"
    When the caller sends a request to the surface with a valid token and header "<header>" set to "kept"
    Then the response status is 200
    And managed agent "bravo" received header "<header>" with value "kept"

    Examples:
      | header        |
      | x-api-key     |
      | x-caller-keys |

  Scenario: An API key caller gets no caller key
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "API Key" source authentication
    And the surface derives caller keys from secret "caller-keys"
    When the caller sends a request to the surface with a valid API key and header "x-caller-key" set to "forged"
    Then the response status is 200
    And managed agent "bravo" did not receive header "x-caller-key"

  Scenario Outline: A caller whose JWT was not verified gets no caller key
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface is stored with a public Access Point
    And the surface derives caller keys from secret "caller-keys"
    When the caller sends a request to the surface <credential condition>
    Then the response status is 200
    And managed agent "bravo" did not receive header "x-caller-key"

    Examples:
      | credential condition  |
      | without a token       |
      | with a tampered token |

  Scenario: A request whose caller key secret cannot be read goes on without a caller key
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives caller keys from secret "caller-keys", which is not stored
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" did not receive header "x-caller-key"
    And the gateway log has a warning containing "Forwarding without the caller key"

  Scenario: A caller key sent to a plain http Target is logged while https Targets are not enforced
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives caller keys from secret "caller-keys"
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the caller key of "test-user" in header "x-caller-key" on every request
    And the gateway log has a warning containing "Caller key sent to a Target that is not https; it will be withheld once credential_policy.target_https is enforce"

  Scenario: A caller key is withheld from a plain http Target when https Targets are enforced
    Given the gateway enforces the credential rule "target_https"
    And an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives caller keys from secret "caller-keys"
    And the gateway keeps its log of warnings
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" did not receive header "x-caller-key"
    And the gateway log has a warning containing "Caller key withheld: the Target is not https and credential_policy.target_https is enforce"

  Scenario: The REST API behind a proxy:// MCP Target gets no caller key
    Given REST API "bravo" exposes a Weather OpenAPI
    And MCP surface "alpha" exists for route "/example" targeting an MCP proxy endpoint backed by REST API "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives caller keys from secret "caller-keys"
    When the caller invokes the MCP tool "get_weather" for city "Paris" with a valid token
    Then the response status is 200
    And REST API "bravo" received "GET /weather/Paris"
    And REST API "bravo" did not receive header "x-caller-key"
