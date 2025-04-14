package edu.ecom.authz.security.dto;

import java.util.Map;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Data
@Builder
public class AuthDetails {
  WebAuthenticationDetails webAuthenticationDetails;
  Map<String, Object> claims;
}
