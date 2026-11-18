package com.careercompass.service.implementation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
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

    private static final RedisScript<String> ROTATE_SCRIPT = new DefaultRedisScript<>("""
            local value = redis.call('GET', KEYS[1])
            if not value then
              return 'INVALID'
            end

            local userId, familyId = string.match(value, '^([^:]+):(.+)$')
            local familyKey = ARGV[3] .. familyId
            local current = redis.call('GET', familyKey)

            if current ~= ARGV[1] then
              if current then
                redis.call('DEL', ARGV[4] .. current)
              end
              redis.call('DEL', familyKey)
              return 'REUSED'
            end

            redis.call('SET', KEYS[2], value, 'EX', ARGV[5])
            redis.call('SET', familyKey, ARGV[2], 'EX', ARGV[5])
            return 'OK:' .. userId
            """, String.class);

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

        String oldHash = hash(raw);
        String newRaw = newRawToken();
        String newHash = hash(newRaw);

        String result = redis.execute(
                ROTATE_SCRIPT,
                List.of(TOKEN_KEY + oldHash, TOKEN_KEY + newHash), // KEYS[1], KEYS[2]
                oldHash, // ARGV[1]
                newHash, // ARGV[2]
                FAMILY_KEY, // ARGV[3]
                TOKEN_KEY, // ARGV[4]
                String.valueOf(ttl.getSeconds())); // ARGV[5]

        if (result == null || !result.startsWith("OK:")) {
            return Optional.empty(); // INVALID or REUSED -> controller returns 401
        }

        Long userId = Long.valueOf(result.substring(3));
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