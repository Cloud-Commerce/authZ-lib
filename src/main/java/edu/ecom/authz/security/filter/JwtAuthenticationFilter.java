package edu.ecom.authz.security.filter;

import edu.ecom.authz.security.dto.AuthDetails;
import edu.ecom.authz.security.dto.TokenDetails;
import edu.ecom.authz.model.UserDetailsImpl;
import edu.ecom.authz.security.RequestMetadata;
import edu.ecom.authz.security.service.JwtServiceProvider;
import edu.ecom.authz.security.service.TokenManagementService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtServiceProvider jwtServiceProvider;
  private final TokenManagementService tokenManagementService;
  private final RequestMetadata requestMetadata;
  private final String[] publicEndpoints;

  @Autowired
  public JwtAuthenticationFilter(JwtServiceProvider jwtServiceProvider,
      TokenManagementService tokenManagementService, RequestMetadata requestMetadata, String[] publicEndpoints) {
    this.jwtServiceProvider = jwtServiceProvider;
    this.tokenManagementService = tokenManagementService;
    this.requestMetadata = requestMetadata;
    this.publicEndpoints = publicEndpoints;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    if (!requiresAuthentication(request)) {
      filterChain.doFilter(request, response);
      return;
    }
    try {
      TokenDetails tokenDetails = Optional.ofNullable(extractToken(request))
          .map(jwtServiceProvider::parseToken).orElseThrow(() -> new ServletException("Missing Token"));

      if (!tokenDetails.isGenuine()) {
        throw new ServletException("Invalid Token");
      }

      Claims claims = tokenDetails.getClaims();

      if(tokenManagementService.isTokenBlacklisted(claims.getId()))
        throw new ServletException("Expired Session : User Logged out!");

      if(tokenDetails.isExpired()) {
        if(requestMetadata.generateClientFingerprint().equals(tokenDetails.getClaims().get("fp"))) {
          throw new ServletException("Expired Token"); // TODO - implementation to be changed
        } else {
          throw new ServletException("Token stolen");
        }
      }

      String username = claims.getSubject();
      Collection<? extends GrantedAuthority> authorities = jwtServiceProvider.extractAuthorities(claims);

      UserDetails userDetails = new UserDetailsImpl(null, username, tokenDetails.getToken(), authorities); // user password not needed here

      UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
          userDetails, null, userDetails.getAuthorities()); // synced with UsernamePasswordAuthenticationFilter strategy
      WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetailsSource().buildDetails(request);

      authentication.setDetails(AuthDetails.builder().webAuthenticationDetails(
          webAuthenticationDetails).claims(claims).build());

      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (Exception ex) {
      // Log the exception
      logger.error("Could not set user authentication in security context: {}", ex);
    }

    filterChain.doFilter(request, response);
  }

  private boolean requiresAuthentication(HttpServletRequest request) {
    return Arrays.stream(publicEndpoints).map(AntPathRequestMatcher::new)
        .noneMatch(requestMatcher -> requestMatcher.matches(request));
  }

  private String extractToken(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
      return bearerToken.split(" ")[1];
    }
    return null;
  }
}
