Feature: Transit Point identity from its caller's credential over Fabric
  A Transit Point that takes the managed agent's DID from the API key its caller presented
  sends only that key's identity to the peer gateway, whatever identity the request copied.

  Scenario: A caller with a copied identity presentation reaches the peer with the DID of its own key
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And gateway 1 has an A2A surface "charlie" targeting managed agent "delta"
    And surface "charlie" has A2A Transit Point "tr1" over Fabric to gateway 2 surface "alpha"
    And gateway 1 surface "charlie" has managed identity enabled
    And gateway 1 has an A2A surface "echo" targeting managed agent "foxtrot"
    And surface "echo" has A2A Transit Point "tr2" over Fabric to gateway 2 surface "alpha"
    And Transit Point "tr2" authenticates its callers with API key "foxtrot-key"
    And Transit Point "tr2" takes the managed agent's identity from its caller's API key
    And managed agent "foxtrot" has obtained the identity presentation that gateway 1 issued for managed agent "delta"
    When managed agent "foxtrot" sends an A2A message/send request through Transit Point "tr2" with header "x-api-key" set to "foxtrot-key"
    Then the response status is 200
    And managed agent "bravo" received the forwarded request with a VP proving only the API key Transit Point "tr2" verified
