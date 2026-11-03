package com.careercompass.service;

import java.time.Duration;
import java.util.Optional;

import com.careercompass.dto.RotationResult;

public interface RefreshTokenService {
    String issueRefreshToken(Long userId);

    Optional<RotationResult> rotate(String refreshToken);

    void revoke(String refreshToken);

    Duration getTtl();

    
}