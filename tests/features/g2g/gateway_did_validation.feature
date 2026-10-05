Feature: Gateway DID validation over Fabric
  A gateway sends fabric envelopes from a per-pairing Connection Point DID but
  signs identity credentials with its gateway DID. The receiving gateway only
  attributes an identity presentation to the peer that sent the envelope.

  Scenario: A new pairing records the peer issuer DID on both gateways
    Given a fabric with 2 gateways
    When the operator reads the Remote gateway records on both gateways
    Then gateway 1 has recorded gateway 2's gateway DID as the issuer DID of gateway 2
    And gateway 2 has recorded gateway 1's gateway DID as the issuer DID of gateway 1

  Scenario: A gateway answers an issuer request from its paired peer
    Given a fabric with 2 gateways
    And gateway 1 has no issuer DID recorded for gateway 2
    When gateway 1 requests the issuer DID of gateway 2
    Then the issuer DID reported by gateway 2 equals gateway 2's gateway DID
    And gateway 1 has recorded gateway 2's gateway DID as the issuer DID of gateway 2

  Scenario: A legacy pairing obtains the peer issuer DID on the first fabric request
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And surface "alpha" has a policy that requires the caller identity to be issued by gateway 1
    And gateway 2 has no issuer DID recorded for gateway 1
    When managed agent "delta" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request carrying an identity presentation issued by gateway 1
    And gateway 2 has recorded gateway 1's gateway DID as the issuer DID of gateway 1

  Scenario: A legacy pairing obtains the peer issuer DID when the gateway restarts
    Given a fabric with 2 gateways
    And gateway 2 has no issuer DID recorded for gateway 1
    When gateway 2 restarts
    Then gateway 2 has recorded gateway 1's gateway DID as the issuer DID of gateway 1

  Scenario: An identity presentation issued by the sending gateway is attributed to the caller
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And surface "alpha" has a policy that requires the caller identity to be issued by gateway 1
    When managed agent "delta" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request carrying an identity presentation issued by gateway 1

  Scenario: A peer gateway cannot replay an identity presentation issued by another gateway
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And surface "echo" has A2A Transit Point "tr2" over Fabric to gateway 2 surface "alpha"
    And surface "alpha" has a policy that requires the caller identity to be issued by gateway 1
    And managed agent "foxtrot" has obtained the identity presentation that gateway 1 issued for managed agent "delta"
    When managed agent "foxtrot" sends an A2A message/send request through Transit Point "tr2"
    Then the response status is 403
    And managed agent "bravo" did not receive a forwarded message

  Scenario: An issuer trusted for a connection is attributed when its presentation arrives over that connection
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And surface "echo" has A2A Transit Point "tr2" over Fabric to gateway 2 surface "alpha"
    And gateway 3 surface "echo" has managed identity enabled
    And surface "alpha" has a policy that requires the caller identity to be issued by gateway 3
    And managed agent "delta" has obtained the identity presentation that gateway 3 issued for managed agent "foxtrot"
    And gateway 2 trusts gateway 3's gateway DID as an issuer of its connection with gateway 1
    When managed agent "delta" sends an A2A message/send request through Transit Point "tr1"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request carrying an identity presentation issued by gateway 3

  Scenario: An issuer trusted for one connection does not admit a replay over another connection
    Given a fabric with 3 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And gateway 3 has an A2A surface "echo" targeting managed agent "foxtrot"
    And surface "echo" has A2A Transit Point "tr2" over Fabric to gateway 2 surface "alpha"
    And surface "alpha" has a policy that requires the caller identity to be issued by gateway 1
    And managed agent "foxtrot" has obtained the identity presentation that gateway 1 issued for managed agent "delta"
    And gateway 2 trusts gateway 1's gateway DID as an issuer of its connection with gateway 1
    When managed agent "foxtrot" sends an A2A message/send request through Transit Point "tr2"
    Then the response status is 403
    And managed agent "bravo" did not receive a forwarded message
