package com.careercompass.service.implementation;

import java.time.Duration;
import java.util.Date;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.careercompass.service.TokenBlackListService;

@Service
public class TokenBlackListServiceImpl implements TokenBlackListService {

    private static final String PREFIX = "blacklist:";

    private final StringRedisTemplate redisTemplate;

    public TokenBlackListServiceImpl(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void blackList(String jti, Date expiration) {
        long remainingMs = expiration.getTime() - System.currentTimeMillis();
        if (remainingMs > 0) {
            redisTemplate.opsForValue().set(PREFIX + jti, "1", Duration.ofMillis(remainingMs));
        }
    }

    @Override
    public boolean isBlackListed(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX+jti));
    }

}
