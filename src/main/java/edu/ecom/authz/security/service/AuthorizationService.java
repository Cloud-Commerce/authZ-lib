package edu.ecom.authz.security.service;

import edu.ecom.authz.security.dto.TokenDetails;
import org.springframework.lang.NonNull;
import reactor.core.publisher.Mono;

public interface AuthorizationService {
    Mono<TokenDetails> getAuthorizedClaims(@NonNull String token, @NonNull String requiredRole);
    Mono<TokenDetails> hasPermission(@NonNull String token, @NonNull String requiredPermission);
}