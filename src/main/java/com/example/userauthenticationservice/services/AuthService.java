package com.example.userauthenticationservice.services;

import com.example.userauthenticationservice.models.User;
import com.example.userauthenticationservice.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService implements IAuthService {

    private final UserRepository userRepository;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public AuthService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public User signup(String email, String password) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            return userOptional.get();
        }

        User user = new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        userRepository.save(user);

        return user;
    }

    @Override
    public User login(String email, String password) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            return null;
        }

        if (!bCryptPasswordEncoder.matches(password, userOptional.get().getPassword())) {
            return null;
        }

        return userOptional.get();
    }
}
