package com.careercompass.service.implementation;

import java.sql.SQLException;
import java.util.Locale;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.careercompass.dto.RegisterRequest;
import com.careercompass.exceptions.UserAlreadyExistsException;
import com.careercompass.model.User;
import com.careercompass.repository.UserRepository;
import com.careercompass.service.UserService;
@Service 
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
    
}
