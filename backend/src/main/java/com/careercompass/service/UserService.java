package com.careercompass.service;

import com.careercompass.dto.AuthResponse;
import com.careercompass.dto.LoginRequest;
import com.careercompass.dto.RegisterRequest;

public interface UserService {

    void registerUser(RegisterRequest request);

    AuthResponse loginUser(LoginRequest request);

    AuthResponse refresh(String refreshToken);

    void logout(String accessToken, String refreshToken);
}
