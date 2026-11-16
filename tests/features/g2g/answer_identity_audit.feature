Feature: The identity on a Fabric answer is audited by the calling gateway
  A surface whose Target is a surface on a paired gateway checks the identity
  presentation that gateway attaches to its managed agent's answer. The VP Audit
  Log of the calling gateway records an answer it can attribute to the answering
  agent, and records why when it cannot.

  Scenario: An answer carrying an identity presentation issued by the answering gateway is recorded as verified
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 2 surface "alpha" has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And the VP Audit Log of gateway 1 keeps every audit event
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And the VP Audit Log of gateway 1 records a verified identity binding issued by gateway 2
    And the VP Audit Log of gateway 1 records the identity presentation received on the answer
    And the VP Audit Log of gateway 1 records the answer's identity under the trace id of the request

  Scenario: A legacy pairing obtains the answering gateway's issuer DID on the first answer
    Given a fabric with 2 gateways
    And gateway 1 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 surface "alpha" has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And gateway 2 has an A2A surface "charlie" forwarding over fabric to gateway 1 surface "alpha"
    And gateway 2 surface "charlie" has managed identity enabled
    And the VP Audit Log of gateway 2 keeps every audit event
    And gateway 2 has no issuer DID recorded for gateway 1
    When the caller sends a Fabric A2A request through gateway 2 surface "charlie"
    Then the response status is 200
    And gateway 2 has recorded gateway 1's gateway DID as the issuer DID of gateway 1
    And the VP Audit Log of gateway 2 records a verified identity binding issued by gateway 1

  Scenario: An answer whose issuer is not trusted on the connection is refused
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 2 surface "alpha" has managed identity enabled
    And managed agent "bravo" response contains the agent-identity extension
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And gateway 1 has recorded "did:example:another-gateway" as the issuer DID of gateway 2
    And the VP Audit Log of gateway 1 keeps every audit event
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 502
    And the VP Audit Log of gateway 1 records a failed identity binding because "its issuer is not trusted on that connection"
    And the VP Audit Log of gateway 1 records no identity presentation received on the answer

  Scenario: An answer carrying the agent identity without a presentation records no identity for the answer
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And managed agent "bravo" response contains the agent-identity extension
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And the VP Audit Log of gateway 1 keeps every audit event
    When the caller sends a Fabric A2A request through gateway 1 surface "charlie"
    Then the response status is 200
    And the VP Audit Log of gateway 1 records no identity binding for the answer
    And the VP Audit Log of gateway 1 records no identity presentation received on the answer
