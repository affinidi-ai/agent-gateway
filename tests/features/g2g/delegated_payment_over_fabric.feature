Feature: Delegated payment over Fabric
  A surface that delegates its payment to a payment gateway sends that gateway the headers the
  Access Point would send its own Target, and the caller's Payment credential.

  Background:
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" delegates payment to gateway 2 surface "alpha"

  Scenario: The payment gateway receives none of the caller's other credentials
    When the caller sends an A2A request to gateway 1 surface "charlie" with headers
      | authorization       | Bearer caller-access-token |
      | proxy-authorization | Basic cHJveHk6c2VjcmV0     |
      | x-transit-token     | caller-transit-token       |
      | x-caller-did        | did:web:caller.example     |
      | x-request-note      | kept                       |
    Then the response status is 200
    And managed agent "bravo" received header "x-request-note" with value "kept"
    And managed agent "bravo" did not receive header "authorization"
    And managed agent "bravo" did not receive header "proxy-authorization"
    And managed agent "bravo" did not receive header "x-transit-token"
    And managed agent "bravo" did not receive header "x-caller-did"

  Scenario: The payment gateway receives the caller's Payment credential
    When the caller sends an A2A request to gateway 1 surface "charlie" with headers
      | authorization | Payment caller-payment-credential |
    Then the response status is 200
    And managed agent "bravo" received header "authorization" with value "Payment caller-payment-credential"
