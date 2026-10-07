# Run by scripts/mcp-conformance/run.sh (target "fabric") through the g2g BDD
# runner. It is kept out of tests/features/g2g because it needs the reference
# server and upstream shim the runner starts.
Feature: The MCP conformance suite passes across two gateways over the Fabric
  Scenario: An Access Point forwards the suite over the Fabric to a surface fronting the reference server
    Given a fabric with 2 gateways
    And gateway 2 has an MCP surface "conformance-remote" targeting the MCP conformance reference server
    And surface "conformance-remote" accepts MCP Origins of gateway 1
    And gateway 1 has an MCP surface "conformance-fabric" forwarding over fabric to gateway 2 surface "conformance-remote"
    When the MCP conformance suite runs against gateway 1 surface "conformance-fabric"
    Then the MCP conformance suite passes
