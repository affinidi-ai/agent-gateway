Feature: Delegated credentials stay under the Target base path over Fabric
  A gateway receiving a Fabric forward sends a delegated credential only to a
  path under its Target's base path. A request whose path climbs out of it is
  refused before any credential is resolved.

  Scenario: gateway 2 refuses a Fabric request whose path leaves the Target base path before releasing a service credential
    Given a fabric with 2 gateways
    And gateway 2 has an A2A surface "alpha" targeting managed agent "bravo"
    And surface "alpha" targets base path "/base" on its Target
    And surface "alpha" sends a service credential from API-key provider "vendor-key" as header "x-vendor-key"
    And gateway 1 has an A2A surface "charlie" forwarding over fabric to gateway 2 surface "alpha"
    And the VP Audit Log of gateway 2 keeps every audit event
    When the caller sends a POST request with an A2A message body to gateway 1 surface "charlie" raw path "/%2e%2e/admin"
    Then the response status is 400
    And the response reason is "target_path_refused"
    And managed agent "bravo" was not called
    And the VP Audit Log of gateway 2 records that a Fabric request to surface "alpha" was refused with reason "target_path_refused"
