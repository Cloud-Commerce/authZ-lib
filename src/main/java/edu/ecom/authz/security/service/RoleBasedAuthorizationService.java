package edu.ecom.authz.security.service;

import edu.ecom.authz.client.AuthenticationServiceClient;
import edu.ecom.authz.security.dto.TokenDetails;
import java.util.Collection;
import java.util.Optional;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class RoleBasedAuthorizationService implements AuthorizationService {

  private final AuthenticationServiceClient authenticator;

    // @Lazy removed as reactive calls shouldn't need it
    public RoleBasedAuthorizationService(AuthenticationServiceClient authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    public Mono<TokenDetails> getAuthorizedClaims(@NonNull String token, @NonNull String requiredRole) {
        return authenticator.verifyToken(token)  // Assume this now returns Mono<TokenDetails>
            .filter(TokenDetails::isGenuine)
            .flatMap(tokenDetails -> {
                Collection<String> roles = tokenDetails.getRoles();

                if (Optional.ofNullable(roles).filter(r -> r.contains(requiredRole)).isPresent()) {
                    return Mono.just(tokenDetails);
                }
                return Mono.empty();
            });
    }

    @Override
    public Mono<TokenDetails> hasPermission(@NonNull String token, @NonNull String requiredPermission) {
        return Mono.empty(); // Implement permission logic as needed
    }
}