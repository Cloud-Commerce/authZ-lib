package edu.ecom.authz.security.service;

import edu.ecom.authz.security.dto.TokenDetails;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class TokenSessionManagementService {

  private final RedisTemplate<String, TokenDetails> redisTemplate;
  private final JwtServiceProvider jwtServiceProvider;

  @Autowired
  public TokenSessionManagementService(RedisTemplate<String, TokenDetails> redisTemplate,
      JwtServiceProvider jwtServiceProvider) {
    this.redisTemplate = redisTemplate;
    this.jwtServiceProvider = jwtServiceProvider;
  }

  public void addActiveSession(TokenDetails tokenDetails) {
    long ttlInMillis = tokenDetails.getExpiration().getTime() - System.currentTimeMillis();
    redisTemplate.opsForValue().set(getSessionKeyForUser(tokenDetails.getUsername(), tokenDetails.getId()),
        tokenDetails, ttlInMillis, TimeUnit.MILLISECONDS);
  }

  private static String getSessionKeyForUser(String username, String jti) {
    return String.format("user:sessions:%s:%s", username, jti);
  }

  public void markAsBlacklisted(String username, String jti, Date expiration) {
    String globalBlacklistKey = getGlobalBlacklistKey(jti);
    TokenDetails value = TokenDetails.builder().state("Blacklisted").build();
    long ttlInMillis = expiration.getTime() - System.currentTimeMillis() + 100;
    redisTemplate.opsForValue().set(globalBlacklistKey, value, ttlInMillis, TimeUnit.MILLISECONDS);
    redisTemplate.delete(getSessionKeyForUser(username, jti));
  }

  private static String getGlobalBlacklistKey(String jti) {
    return "jwt:blacklist:" + jti;
  }

  public boolean isTokenBlacklisted(String jti) {
    return Boolean.TRUE.equals(redisTemplate.hasKey(getGlobalBlacklistKey(jti)));
  }

  public int getActiveSessionCountForUser(String username) {
    return Objects.requireNonNull(getKeysByPrefix(getSessionKeyForUser(username, ""))).size();
  }

  public void invalidateAllTokensForUser(String username) {
//    getKeyValuesByPrefix(getSessionKeyForUser(username, "")).forEach((key, tokenDetails) -> {
//      markAsBlacklisted(tokenDetails.getId(), tokenDetails.getExpiresAt());
//      redisTemplate.delete(key);
//    });

    List<String> activeSessionKeysByPrefix = getKeysByPrefix(getSessionKeyForUser(username, ""));
    activeSessionKeysByPrefix.stream().map(redisTemplate.opsForValue()::getAndDelete)
        .filter(Objects::nonNull).forEach(tokenDetails -> markAsBlacklisted(username, tokenDetails.getId(), tokenDetails.getExpiration()));
  }

  private Map<String, TokenDetails> getKeyValuesByPrefix(String prefix) {
    List<String> keys = getKeysByPrefix(prefix);
    return Objects.requireNonNull(redisTemplate.opsForValue().multiGet(keys)).stream()
        .collect(Collectors.toMap(v -> getSessionKeyForUser(v.getUsername(), v.getId()), tokenDetails -> tokenDetails));
  }

  private List<String> getKeysByPrefix(String prefix) {
    List<String> keys = new ArrayList<>();
    ScanOptions scanOptions = ScanOptions.scanOptions()
        .match(prefix + "*") // Prefix pattern
        .count(10) // Batch size (adjust based on Redis size)
        .build();

    // Iterate using a Cursor
    try (Cursor<String> cursor = redisTemplate.scan(scanOptions)) {
      while (cursor.hasNext()) {
        keys.add(cursor.next());
      }
    } catch (Exception e) {
      throw new RuntimeException("Failed to scan Redis keys", e);
    }
    return keys;
  }

  public TokenDetails createNewStatelessSession(Authentication authentication) {
    TokenDetails tokenDetails = jwtServiceProvider.generateToken(authentication);
    addActiveSession(tokenDetails);
    return tokenDetails;
  }
}