Feature: Kafka connection settings of a stream integration endpoint
  A Kafka stream endpoint names how its producer reaches the brokers: `security_protocol`
  (plaintext, ssl, sasl_plaintext or sasl_ssl) and, for a SASL protocol, `sasl_mechanism`
  (PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512) with a SASL username and password. The admin API
  refuses an endpoint whose connection settings the producer could not use.

  Background:
    Given the operator can use the admin API and no surface is configured for route "/example"

  Scenario: A Kafka endpoint with an unknown security protocol is refused
    When the operator creates a Kafka stream endpoint with security protocol "SASL_SSL" and SASL mechanism "SCRAM-SHA-512"
    Then the admin API response status is 400
    And the admin API error response mentions "security_protocol must be one of plaintext, ssl, sasl_plaintext or sasl_ssl"

  Scenario: A Kafka endpoint with an unknown SASL mechanism is refused
    When the operator creates a Kafka stream endpoint with security protocol "sasl_ssl" and SASL mechanism "OAUTHBEARER"
    Then the admin API response status is 400
    And the admin API error response mentions "sasl_mechanism must be one of PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512"

  Scenario: A Kafka endpoint using SASL over TLS with SCRAM-SHA-512 is stored
    When the operator creates a Kafka stream endpoint with security protocol "sasl_ssl" and SASL mechanism "SCRAM-SHA-512"
    Then the admin API response status is 201
    And the endpoint in the admin API response connects with security protocol "sasl_ssl" and SASL mechanism "SCRAM-SHA-512"
    And the endpoint in the admin API response does not show its SASL password
