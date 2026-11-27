Feature: SAML configuration at startup
  In SAML mode the gateway refuses to start when saml.json asks for encrypted assertions or sets a
  single logout URL, since it supports neither, and its output names the setting. A saml.json key
  the gateway does not read is ignored and named in one startup warning, without its value.

  Background:
    Given human users sign in with SAML

  Scenario: A saml.json that requires encrypted assertions stops the gateway at startup
    Given saml.json sets "require_encrypted_assertions" to true
    When the gateway tries to start
    Then the gateway refuses to start, naming "require_encrypted_assertions"

  Scenario: A saml.json that sets a single logout URL stops the gateway at startup
    Given saml.json sets "idp_slo_url" to "https://idp.example.test/slo"
    When the gateway tries to start
    Then the gateway refuses to start, naming "idp_slo_url"

  Scenario: A saml.json whose default_role is not a gateway role stops the gateway at startup
    Given saml.json sets "default_role" to "Administrator"
    When the gateway tries to start
    Then the gateway refuses to start, naming "default_role"

  Scenario: A saml.json that maps an identity provider role to a misspelled gateway role stops the gateway at startup
    Given saml.json maps the identity provider role "gw-admins" to "Administrator"
    When the gateway tries to start
    Then the gateway refuses to start, naming "gw-admins"

  Scenario: A saml.json key the gateway does not read is named in a startup warning
    Given saml.json sets "idp_sso_urll" to "bdd-unread-setting-value"
    When the gateway starts
    Then the gateway log has a warning containing "idp_sso_urll"
    And the gateway log does not contain "bdd-unread-setting-value"
