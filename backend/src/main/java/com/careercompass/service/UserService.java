package com.careercompass.service;

import org.springframework.stereotype.Service;

import com.careercompass.dto.LoginRequest;
import com.careercompass.dto.LoginResponse;
import com.careercompass.dto.RegisterRequest;

import ch.qos.logback.core.net.LoginAuthenticator;

public interface UserService {
    
    void registerUser(RegisterRequest request);

    LoginResponse loginUser(LoginRequest request);
}
