Feature: No OpenID Connect sign-in outside OIDC mode
  The OpenID Connect sign-in, sign-in link and logout routes exist only when human users sign in
  with OpenID Connect. With passkeys or SAML, opening them finds nothing: no redirect to a provider
  and no binding cookie.

  Scenario: A gateway whose human users sign in with passkeys offers no OpenID Connect sign-in
    When a browser opens the OpenID Connect sign-in routes
    Then the gateway offers no OpenID Connect sign-in

  Scenario: A gateway whose human users sign in with SAML offers no OpenID Connect sign-in
    Given human users sign in with SAML
    When a browser opens the OpenID Connect sign-in routes
    Then the gateway offers no OpenID Connect sign-in
