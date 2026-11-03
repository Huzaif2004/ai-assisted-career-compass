package com.careercompass.service.implementation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.careercompass.dto.RotationResult;
import com.careercompass.service.RefreshTokenService;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {
    private static final String TOKEN_KEY = "refresh:"; // refresh:<hash> → "userId:familyId"
    private static final String FAMILY_KEY = "family:"; // family:<familyId> → <hash of current token>
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redis;
    private final Duration ttl;

    public RefreshTokenServiceImpl(StringRedisTemplate redis,
            @Value("${jwt.refresh-ttl-days}") long ttlDays) {
        this.redis = redis;
        this.ttl = Duration.ofDays(ttlDays);
    }

    @Override
    public String issueRefreshToken(Long userId) {
        String familyId = UUID.randomUUID().toString();
        String token = UUID.randomUUID().toString();
        String hash = hash(token);
        redis.opsForValue().set(TOKEN_KEY + hash, userId + ":" + familyId, ttl);
        redis.opsForValue().set(FAMILY_KEY + familyId, hash, ttl);
        return token;
    }

    @Override
    public Optional<RotationResult> rotate(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }

        // 1. Is it a token we issued?
        String oldHash = hash(raw);
        String value = redis.opsForValue().get(TOKEN_KEY + oldHash); // "42:familyId"
        if (value == null) {
            return Optional.empty(); // fake or expired(after 7 days the record is gone)
        }
        String[] parts = value.split(":", 2);
        Long userId = Long.valueOf(parts[0]);
        String familyId = parts[1];

        // 2. Is it the CURRENT token of its family?
        String current = redis.opsForValue().get(FAMILY_KEY + familyId);
        if (!oldHash.equals(current)) {
            redis.delete(FAMILY_KEY + familyId); // reuse: break the chain
            return Optional.empty();
        }

        // 3. Create the next token and move the pointer
        String newRaw = newRawToken();
        String newHash = hash(newRaw);
        redis.opsForValue().set(TOKEN_KEY + newHash, value, ttl); // new token record
        redis.opsForValue().set(FAMILY_KEY + familyId, newHash, ttl); // pointer: old -> new

        return Optional.of(new RotationResult(userId, newRaw));
    }

    @Override
    public void revoke(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return;
        }

        String value = redis.opsForValue().get(TOKEN_KEY + hash(refreshToken)); // "42:familyId"
        if (value == null) {
            return; // unknown or expired token
        }

        String familyId = value.split(":", 2)[1];
        redis.delete(FAMILY_KEY + familyId);
    }

    @Override
    public Duration getTtl() {
        return ttl;
    }

    private String newRawToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String raw) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(sha.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}