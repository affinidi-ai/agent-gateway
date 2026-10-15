Feature: Identity bindings are audited
  The gateway that receives a request over fabric checks the identity
  presentation the sending gateway attached when a surface policy relies on it.
  The VP Audit Log records a presentation it can rely on, and records why when
  it cannot.

  Scenario: An identity presentation issued by the sending gateway is recorded as verified
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And surface "alpha" has a policy that requires the caller identity to be issued by gateway 1
    And the VP Audit Log of gateway 2 keeps every audit event
    When managed agent "delta" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request carrying an identity presentation issued by gateway 1
    And the VP Audit Log of gateway 2 records a verified identity binding issued by gateway 1

  Scenario: A request without the identity presentation a surface policy requires is recorded as a failed identity binding
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And surface "alpha" has a policy that requires the caller identity to be issued by gateway 1
    And the VP Audit Log of gateway 2 keeps every audit event
    When managed agent "delta" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 403
    And managed agent "bravo" did not receive a forwarded message
    And the VP Audit Log of gateway 2 records a failed identity binding because "no identity presentation was sent"

  Scenario: A replayed identity presentation is recorded as a failed identity binding
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And surface "echo" has A2A Transit Point "tr2" over Fabric to gateway 2 surface "alpha"
    And surface "alpha" has a policy that requires the caller identity to be issued by gateway 1
    And managed agent "foxtrot" has obtained the identity presentation that gateway 1 issued for managed agent "delta"
    And the VP Audit Log of gateway 2 keeps every audit event
    When managed agent "foxtrot" sends an A2A message/send request through Transit Point "tr2"
    Then the response status is 403
    And managed agent "bravo" did not receive a forwarded message
    And the VP Audit Log of gateway 2 records a failed identity binding because "its identity presentation failed verification"
