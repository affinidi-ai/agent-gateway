Feature: Policy changes are audited
  Each change an operator makes to a policy definition, or to where a policy
  definition applies, is recorded in the VP Audit Log with the operator as its
  actor. A change the operator may not make is refused and recorded as refused.

  Background:
    Given A2A surface "alpha" exists for route "/example" with managed agent "bravo" as its target
    And the VP Audit Log keeps every audit event

  Scenario: Creating a policy definition is recorded
    When the operator creates a surface policy definition
    Then the admin API response status is 201
    And the VP Audit Log records that the operator created the policy definition

  Scenario: Adding a policy definition to a surface is recorded
    Given the operator has created a surface policy definition
    When the operator adds the policy definition to surface "alpha" as its request policy
    Then the admin API response status is 200
    And the VP Audit Log records that the operator attached the policy definition to surface "alpha" as its request policy

  Scenario: Changing a policy definition's Rego is recorded
    Given the operator has created a surface policy definition
    When the operator changes the policy definition's Rego
    Then the admin API response status is 200
    And the VP Audit Log records that the operator changed the policy definition's Rego

  Scenario: Removing a policy definition from a surface is recorded
    Given the operator has created a surface policy definition
    And the operator has added the policy definition to surface "alpha" as its request policy
    When the operator removes the request policy from surface "alpha"
    Then the admin API response status is 200
    And the VP Audit Log records that the operator detached the policy definition from surface "alpha"

  Scenario: Deleting a policy definition is recorded
    Given the operator has created a surface policy definition
    When the operator deletes the policy definition
    Then the admin API response status is 204
    And the VP Audit Log records that the operator deleted the policy definition

  Scenario: A policy change the operator may not make is refused and recorded
    Given operator "uma" has the "user" role
    When operator "uma" creates a surface policy definition
    Then the admin API response status is 403
    And the VP Audit Log records that operator "uma" was refused creating a policy definition
    And the VP Audit Log has no record that the policy definition was created
