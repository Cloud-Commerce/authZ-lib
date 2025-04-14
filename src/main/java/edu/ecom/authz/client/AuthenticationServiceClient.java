package edu.ecom.authz.client;

import edu.ecom.authz.security.dto.TokenDetails;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceClient {

  private final WebClient.Builder webClientBuilder;

  public Mono<TokenDetails> verifyToken(String token) {
    return webClientBuilder.build()
        .post()
        .uri("http://authn-service/api/auth/verify") // Service name from Eureka
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
        .retrieve()
        .onStatus(HttpStatusCode::is4xxClientError,
            response -> Mono.error(new RuntimeException("Client error")))
        .onStatus(HttpStatusCode::is5xxServerError,
            response -> Mono.error(new RuntimeException("Server error")))
        .bodyToMono(TokenDetails.class)
        .timeout(Duration.ofSeconds(3)) // Optional timeout
        .retryWhen(Retry.backoff(3, Duration.ofMillis(100))); // Optional retry
  }

}