package edu.ecom.authz.security.dto;

import io.jsonwebtoken.Claims;
import java.util.Date;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenDetails {
  String username;
  String id;
  String token;
  Date issuedAt;
  Date expiration;
  String state;
  String remarks;
  boolean genuine;
  boolean expired;
  Claims claims;
  Map<String, String> clientMetadata;
}
