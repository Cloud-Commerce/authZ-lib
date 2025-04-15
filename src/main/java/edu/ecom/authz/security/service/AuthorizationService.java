package edu.ecom.authz.security.service;

import edu.ecom.authz.security.dto.TokenDetails;
import org.springframework.lang.NonNull;
import reactor.core.publisher.Mono;

public interface AuthorizationService {
    Mono<Boolean> hasRole(@NonNull Mono<TokenDetails> tokenDetailsMono, @NonNull String requiredRole);
    Mono<Boolean> hasPermission(@NonNull Mono<TokenDetails> tokenDetailsMono, @NonNull String requiredPermission);
}