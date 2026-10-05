
Feature: Surface-level policy controls inbound A2A traffic


    Background:
        Given gateway "gateway-1"
        And gateway "gateway-1" has surface "alpha" targeting A2A Server agent "agent-managed"
        And surface "alpha" uses path "/example"


    Scenario: Traffic reaches the managed agent when no surface-level policy is defined
        When the caller sends A2A request to the surface path "/example/target" in gateway "gateway-1"
        Then the response status is 200
        And the response body matches agent "agent-managed" response
        And agent "agent-managed" received the forwarded request
        And agent "agent-managed" is called by path "/target"


    Scenario: Request policy allows matching caller traffic to reach the managed agent
        Given A2A surface "alpha" has request policy "sp-agent-1" that allows inbound requests only to "/target/allowed"
        When the caller sends A2A request to the surface path "/example/target/allowed/path" in gateway "gateway-1"
        Then the response status is 200
        And the response body matches agent "agent-managed" response
        And agent "agent-managed" received the forwarded request
        And agent "agent-managed" is called by path "/target/allowed/path"


    Scenario: Request policy blocks non-matching caller traffic before it reaches the managed agent
        Given A2A surface "alpha" has request policy "sp-agent-1" that allows inbound requests only to "/target/allowed"
        When the caller sends A2A request to the surface path "/example/target/unallowed/path" in gateway "gateway-1"
        Then the response status is 403
        And agent "agent-managed" was not called
        And the response body is error "request_policy_denied" 


    Scenario: Request policy inspects the A2A message body and allows a matching message
        Given A2A surface "alpha" has request policy "sp-agent-1" that allows inbound requests that contains "hello" in body
        When the caller sends A2A request to the surface path "/example/target/path" in gateway "gateway-1"
        Then the response status is 200
        And the response body matches agent "agent-managed" response
        And agent "agent-managed" received the forwarded request
        And agent "agent-managed" is called by path "/target/path"


   Scenario: Request policy inspects the A2A message body and blocks a non-matching message
        Given A2A surface "alpha" has request policy "sp-agent-1" that allows inbound requests that contains "different" in body
        When the caller sends A2A request to the surface path "/example/target/path" in gateway "gateway-1"
        Then the response status is 403
        And agent "agent-managed" was not called
        And the response body is error "request_policy_denied"


    # ── input.a2a.method is exposed to policy exactly as the caller sent it ──
    #
    # A2A v1.0 renamed the JSON-RPC methods (message/send became SendMessage). The
    # gateway deliberately does NOT canonicalise the method before handing it to
    # policy, so a 1.0-native policy author matches the spelling they actually sent.
    # The four scenarios below pin that both ways: each spelling matches its own era
    # and only its own era. If the gateway ever started rewriting the method to
    # the v0.3 spelling, the first and fourth scenarios would fail; to the v1.0
    # spelling, the second and third.

    Scenario: A policy written for the v1.0 method name matches a v1.0 caller
        Given A2A surface "alpha" has request policy "sp-agent-1" that allows only A2A method "SendMessage"
        When the caller sends A2A method "SendMessage" to the surface path "/example/target/path" in gateway "gateway-1"
        Then the response status is 200
        And agent "agent-managed" received the forwarded request

    Scenario: A policy written for the v1.0 method name does not match a v0.3 caller
        Given A2A surface "alpha" has request policy "sp-agent-1" that allows only A2A method "SendMessage"
        When the caller sends A2A method "message/send" to the surface path "/example/target/path" in gateway "gateway-1"
        Then the response status is 403
        And agent "agent-managed" was not called
        And the response body is error "request_policy_denied"

    Scenario: A policy written for the v0.3 method name matches a v0.3 caller
        Given A2A surface "alpha" has request policy "sp-agent-1" that allows only A2A method "message/send"
        When the caller sends A2A method "message/send" to the surface path "/example/target/path" in gateway "gateway-1"
        Then the response status is 200
        And agent "agent-managed" received the forwarded request

    Scenario: A policy written for the v0.3 method name does not match a v1.0 caller
        # This is the migration consequence customers must know about: an existing
        # policy keeps working for its own era, and to cover both they add an OR of
        # the two spellings.
        Given A2A surface "alpha" has request policy "sp-agent-1" that allows only A2A method "message/send"
        When the caller sends A2A method "SendMessage" to the surface path "/example/target/path" in gateway "gateway-1"
        Then the response status is 403
        And agent "agent-managed" was not called
        And the response body is error "request_policy_denied" 


    Scenario: Response policy allows the managed agent response to reach the caller if content-type is allowed
        Given A2A surface "alpha" has response policy "sp-agent-1" that allows inbound responses whose content-type is "application/json"
        When the caller sends A2A request to the surface path "/example/target/path" in gateway "gateway-1"
        Then the response status is 200
        And the response body matches agent "agent-managed" response
        And agent "agent-managed" received the forwarded request
        And agent "agent-managed" is called by path "/target/path"


    Scenario: Response policy blocks the managed agent response before it reaches the caller if content-type is not allowed
        Given A2A surface "alpha" has response policy "sp-agent-1" that allows inbound responses whose content-type is "super-conent-type"
        When the caller sends A2A request to the surface path "/example/target/path" in gateway "gateway-1"
        Then the response status is 403
        And agent "agent-managed" received the forwarded request
        And agent "agent-managed" is called by path "/target/path"
        And the response body is error "response_policy_denied" 
