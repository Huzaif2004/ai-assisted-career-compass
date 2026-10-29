package com.careercompass.service.implementation;

import java.sql.SQLException;
import java.util.Locale;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.careercompass.dto.LoginRequest;
import com.careercompass.dto.LoginResponse;
import com.careercompass.dto.RegisterRequest;
import com.careercompass.exceptions.InvalidEmailException;
import com.careercompass.exceptions.InvalidPasswordException;
import com.careercompass.exceptions.UserAlreadyExistsException;

import com.careercompass.model.User;
import com.careercompass.repository.UserRepository;
import com.careercompass.security.JwtUtil;
import com.careercompass.service.UserService;
@Service 
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;  
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void registerUser(RegisterRequest request) {
        // Check if the email is already registered
        String emailLowercase=request.email().toLowerCase(Locale.ROOT);
        if (userRepository.findByEmail(emailLowercase).isPresent()) {
            throw new UserAlreadyExistsException("Email is already registered");
        }

        // Create a new User entity and save it to the database
        User user = new User(request.name(), emailLowercase, passwordEncoder.encode(request.password()));
       
        try{

            userRepository.saveAndFlush(user);
        } catch(DataIntegrityViolationException e){
            if (isEmailUniqueConstraintViolation(e)) {
                throw new UserAlreadyExistsException("Email is already registered");
            }
            throw e;
        }
    }

    private boolean isEmailUniqueConstraintViolation(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof org.hibernate.exception.ConstraintViolationException violation
                    && User.EMAIL_UNIQUE_CONSTRAINT.equalsIgnoreCase(violation.getConstraintName())) {
                return true;
            }

            if (cause instanceof SQLException sqlException
                    && sqlException.getErrorCode() == 1062
                    && sqlException.getMessage() != null
                    && sqlException.getMessage().toLowerCase(Locale.ROOT)
                            .contains(User.EMAIL_UNIQUE_CONSTRAINT.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public LoginResponse loginUser(LoginRequest request) {
        if (request.email() == null || request.password() == null) {
            throw new IllegalArgumentException("Email and password must not be null");
        }
        String emailLowercase=request.email().toLowerCase(Locale.ROOT);
        User user = userRepository.findByEmail(emailLowercase)
                .orElseThrow(() -> new InvalidEmailException("Invalid email"));

        if (!passwordEncoder.matches(request.password(),user.getHashedPassword())) {
            throw new InvalidPasswordException("Invalid password");
        }

        String jwtToken = jwtUtil.generateAccessToken(user.getId(), user.getEmail());
        return new LoginResponse(jwtToken, user.getEmail(), user.getName());
    }
    
}
