Feature: Signing in from the OpenID provider's link
  An OpenID provider's portal can link people straight into the dashboard (third-party-initiated
  login). The link names the provider as iss, and may name the account (login_hint) and the
  dashboard page to open (target_link_uri), by GET or by a form the provider's page posts. A link
  that names the configured issuer exactly starts a fresh sign-in at that provider, passes the
  login hint on, and opens only a page on the dashboard's own origin that a sign-in may return to;
  any other page opens the dashboard root. A link that names another provider is refused. Links
  spend the same per-client sign-in budget as the login page.

  Background:
    Given human users sign in with OpenID Connect

  Scenario: Following the provider's link sends the browser to the provider with its login hint
    When a browser follows the provider's sign-in link with the login hint "mallory@example.test"
    Then the browser is sent to the provider with the login hint "mallory@example.test"

  Scenario: The provider's page posts its sign-in link as a form
    When the provider's page posts its sign-in link with the login hint "mallory@example.test"
    Then the browser is sent to the provider with the login hint "mallory@example.test"

  Scenario: Sign-in links spend the per-client sign-in budget the login button shares
    Given a browser has followed the provider's sign-in link 10 times
    When the browser starts a sign-in from the login button
    Then the response status is 429

  Scenario: A sign-in link that names another provider is refused
    When a browser follows a sign-in link that names another provider
    Then the response status is 400

  Scenario: A link opening a dashboard page that a sign-in may return to opens that page
    When "mallory" signs in from the provider's link opening the dashboard page "/access-tokens/new" carrying the roles "gw-all"
    Then the dashboard opens at "/access-tokens/new"

  Scenario: A link opening a page on another site opens the dashboard root instead
    When "mallory" signs in from the provider's link opening "https://evil.example/access-tokens/new" carrying the roles "gw-all"
    Then the dashboard opens at "/"
