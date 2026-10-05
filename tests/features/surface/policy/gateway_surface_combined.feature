
Feature: Gateway-level and surface-level combined policy controls inbound A2A traffic


    Background:
        Given gateway "gateway-1"
        And gateway "gateway-1" has surface "alpha" targeting A2A Server agent "agent-managed"
        And surface "alpha" uses path "/example"


    Scenario: Gateway-level policy allows but surface-level policy blocks caller traffic
        Given gateway "gateway-1" has gateway-level policy that allows inbound requests only to "/target"
        And A2A surface "alpha" has request policy "sp-agent-1" that allows inbound requests only to "/target/allowed"
        When the caller sends A2A request to the surface path "/example/target/unallowed" in gateway "gateway-1"
        Then the response status is 403
        And agent "agent-managed" was not called
        And the response body is error "request_policy_denied" 


    Scenario: Surface-level policy allows but gateway-level policy blocks caller traffic
        Given gateway "gateway-1" has gateway-level policy that allows inbound requests only to "/target/allowed"
        And A2A surface "alpha" has request policy "sp-agent-1" that allows inbound requests only to "/target"
        When the caller sends A2A request to the surface path "/example/target/unallowed" in gateway "gateway-1"
        Then the response status is 403
        And agent "agent-managed" was not called
        And the response body is error "request_denied_gateway_policy" 
