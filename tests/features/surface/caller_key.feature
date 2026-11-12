Feature: Caller keys
  A surface with a caller key sends its Target a key for each caller whose JWT
  the gateway verified on that request. The gateway derives it from a secret in
  its secrets store, the surface, and the caller's issuer and identity claim, so
  the key is the same on every request from that caller and the Target's own
  operator cannot derive it. No other caller gets a key, and a caller key a
  caller sends is never forwarded, whether or not the surface sets a caller key.

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
    And the surface derives caller keys in header "x-user-vault-key" from secret "caller-keys"
    When the caller sends a request to the surface with a valid token
    Then the response status is 200
    And managed agent "bravo" received the caller key of "test-user" in header "x-user-vault-key" on every request
    And managed agent "bravo" did not receive header "x-caller-key"

  Scenario Outline: A caller key the caller sends is replaced by the caller's own key
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    And the surface derives caller keys from secret "caller-keys"
    When the caller sends a request to the surface with a valid token and header "<header>" set to "forged"
    Then the response status is 200
    And managed agent "bravo" received the caller key of "test-user" in header "x-caller-key" on every request
    And managed agent "bravo" did not receive header "x_caller_key"

    Examples:
      | header       |
      | x-caller-key |
      | x_caller_key |

  Scenario Outline: A surface without a caller key does not forward one the caller sends
    Given an A2A surface targeting managed agent "bravo"
    And the surface requires "JWT Bearer" source authentication
    When the caller sends a request to the surface with a valid token and header "<header>" set to "forged"
    Then the response status is 200
    And managed agent "bravo" did not receive header "<header>"

    Examples:
      | header       |
      | x-caller-key |
      | x_caller_key |

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
