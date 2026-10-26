package com.careercompass.service;

import org.springframework.stereotype.Service;

import com.careercompass.dto.RegisterRequest;

public interface UserService {
    
    void registerUser(RegisterRequest request);
}
