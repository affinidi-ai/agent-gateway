
Feature: Gateway-level policy controls inbound A2A traffic


    Background:
        Given gateway "gateway-1"
        And gateway "gateway-1" has surface "alpha" targeting A2A Server agent "agent-managed"
        And surface "alpha" uses path "/example"


    Scenario: A2A inbound call to an allowed path accesses destination when gateways policy allows
        Given gateway "gateway-1" has gateway-level policy that allows inbound requests only to "/target/allowed"
        When the caller sends A2A request to the surface path "/example/target/allowed/path" in gateway "gateway-1"
        Then the response status is 200
        And the response body matches agent "agent-managed" response
        And agent "agent-managed" received the forwarded request
        And agent "agent-managed" is called by path "/target/allowed/path"



    Scenario: A2A inbound call to an unallowed path is blocked when a gateway policy allows only certain paths    
        Given gateway "gateway-1" has gateway-level policy that allows inbound requests only to "/target/allowed"
        When the caller sends A2A request to the surface path "/example/target/unallowed/path" in gateway "gateway-1"
        Then the response status is 403
        And agent "agent-managed" was not called
        And the response body is error "request_denied_gateway_policy" 
