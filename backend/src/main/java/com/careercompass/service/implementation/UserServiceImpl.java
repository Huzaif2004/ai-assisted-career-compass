package com.careercompass.service.implementation;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.careercompass.dto.RegisterRequest;
import com.careercompass.exceptions.UserAlreadyExistsException;
import com.careercompass.model.User;
import com.careercompass.repository.UserRepository;
import com.careercompass.service.UserService;

public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;  
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void registerUser(RegisterRequest request) {
        // Check if the email is already registered
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new UserAlreadyExistsException("Email is already registered");
        }

        // Create a new User entity and save it to the database
        User user = new User(request.name(), request.email(), passwordEncoder.encode(request.password()));
       

        userRepository.save(user);
    }
    
}
