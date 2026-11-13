Feature: Dashboard pages win over gateway.json prefixes
  The dashboard owns its top-level pages. A Surface Prefix, MCP proxy or redirect in
  gateway.json whose prefix would hide one of those pages is not served, so opening that
  page still shows the dashboard. The gateway still starts, serves every other prefix and
  surface, and logs an error naming each prefix it skips and the page that prefix would
  hide. A configuration reload skips such a prefix in the same way and reports it. A path
  under the management API that matches no endpoint is answered 404, not with the dashboard.

  Background:
    Given an A2A surface targeting managed agent "bravo"
    And the gateway serves its dashboard
    And the gateway keeps its log of warnings

  Scenario: An MCP proxy on a dashboard page is not served
    Given the gateway configuration has an MCP proxy at "/settings"
    When a browser opens "/settings/general"
    Then the dashboard page is served
    And the gateway log has an error containing "prefix '/settings' shadows the dashboard page '/settings'"

  Scenario: A redirect on a dashboard page is not served
    Given the gateway configuration redirects "/policies" to "/elsewhere"
    When a browser opens "/policies"
    Then the dashboard page is served
    And the gateway log has an error containing "prefix '/policies' shadows the dashboard page '/policies'"

  Scenario: A Surface Prefix below a dashboard page is not served
    Given the gateway configuration offers the Surface Prefix "/settings/agents"
    When a browser opens "/settings/agents"
    Then the dashboard page is served
    And the gateway log has an error containing "prefix '/settings/agents' shadows the dashboard page '/settings'"

  Scenario: The surface is still served when a prefix is skipped
    Given the gateway configuration has an MCP proxy at "/settings"
    When the caller sends a request to the surface
    Then the response status is 200
    And managed agent "bravo" received the forwarded request

  Scenario: A redirect that hides no dashboard page is served
    Given the gateway configuration redirects "/old-docs" to "/docs"
    When a browser opens "/old-docs"
    Then the browser is redirected to "/docs"
    And the gateway log has no error containing "shadows the dashboard page"

  Scenario: A reload reports a redirect it skips on a dashboard page
    When the operator adds a redirect from "/policies" to "/elsewhere" and reloads the configuration
    Then the reload succeeds and reports "prefix '/policies' shadows the dashboard page '/policies'"

  Scenario: A redirect a reload skips does not hide the dashboard page
    Given the operator has added a redirect from "/policies" to "/elsewhere" and reloaded the configuration
    When a browser opens "/policies"
    Then the dashboard page is served

  Scenario: A management API path that matches no endpoint is not the dashboard
    When a browser opens "/api/v1/no-such-endpoint"
    Then the response status is 404
    And the page says the API path was not found

  Scenario: A dashboard page whose path starts like the management API is still served
    When a browser opens "/api-keys/new"
    Then the dashboard page is served
