package edu.ecom.authz.security.service;

import edu.ecom.authz.security.dto.TokenDetails;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class RoleBasedAuthorizationService implements AuthorizationService {

    @Override
    public Mono<Boolean> hasRole(@NonNull Mono<TokenDetails> tokenDetailsMono, @NonNull String requiredRole) {
        return tokenDetailsMono  // Assume this now returns Mono<TokenDetails>
            .map(TokenDetails::getRoles)
            .filter(roles -> roles.contains(requiredRole))
            .hasElement();
    }

    @Override
    public Mono<Boolean> hasPermission(@NonNull Mono<TokenDetails> tokenDetailsMono,
        @NonNull String requiredPermission) {
        return Mono.just(false); // Implement permission logic as needed
    }
}