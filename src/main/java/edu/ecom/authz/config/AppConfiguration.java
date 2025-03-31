package edu.ecom.authz.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfiguration {

  @Bean("publicEndpoints")
  protected String[] getPublicEndpoints() {
    return new String[]{"/api/auth/**",
        "/actuator/**", "/v3/api-docs/**", "/swagger-ui/**"};
  }

}
