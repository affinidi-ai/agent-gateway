
Feature: Transit-point level policy enforcement


    Background:
        Given gateway "gateway-1" with outbound listener
        And external agent "agent-external"


    Scenario: With no policy, A2A outbound call reaches its external destination
        Given gateway "gateway-1" has surface "alpha" targeting A2A Server agent "agent-managed"
        And surface "alpha" uses path "/example"
        And surface "alpha" has direct A2A transit point "tr1" to agent "agent-external"
        And transit point "tr1" uses path "/example/forward/foo"
        When the caller sends A2A request to the surface path "/example/foo" in gateway "gateway-1"
        Then the response status is 200
        And the response body matches agent "agent-external" response
        And agent "agent-external" received the forwarded request
        And agent "agent-external" is called by path "/example/forward/foo"


    Scenario: A2A outbound call to an unallowed path is blocked when a per-transit point policy allows only certain paths
        Given gateway "gateway-1" has surface "alpha" targeting A2A Server agent "agent-managed"
        And surface "alpha" uses path "/example"
        And surface "alpha" has direct A2A transit point "tr1" to agent "agent-external"
        And transit point "tr1" uses path "/example/forward/unallowed"
        And transit point "tr1" has policy "tp-policy-1" that allows outbound requests only to "/outgoing/agent-external/example/forward/allowed"
        When the caller sends A2A request to the surface path "/example/foo" in gateway "gateway-1"
        Then the response status is 403
        And the response body is error "transit_point_request_policy_denied"
        And agent "agent-managed" received the forwarded request
        And agent "agent-external" was not called


    Scenario: A2A outbound call to an allowed path accesses destination when a per-transit point policy allows only certain paths
        Given gateway "gateway-1" has surface "alpha" targeting A2A Server agent "agent-managed"
        And surface "alpha" uses path "/example"
        And surface "alpha" has direct A2A transit point "tr1" to agent "agent-external"
        And transit point "tr1" uses path "/example/forward/allowed"
        And transit point "tr1" has policy "tp-policy-1" that allows outbound requests only to "/outgoing/agent-external/example/forward/allowed"
        When the caller sends A2A request to the surface path "/example/foo" in gateway "gateway-1"
        Then the response status is 200
        And the response body matches agent "agent-external" response
        And agent "agent-external" received the forwarded request
        And agent "agent-external" is called by path "/example/forward/allowed"
