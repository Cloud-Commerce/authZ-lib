package edu.ecom.authz.security.service;

import org.springframework.stereotype.Component;

@Component
public class RequiredRoleFinderService {

  public String getRequiredRoleForRoute(String requestURI) {
    // Implement logic to map routes to required roles
    return "ROLE_CUSTOMER"; // Example role
  }

}
