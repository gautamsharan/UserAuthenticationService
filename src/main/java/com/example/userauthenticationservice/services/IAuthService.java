package com.example.userauthenticationservice.services;

import com.example.userauthenticationservice.models.User;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.util.MultiValueMap;

public interface IAuthService {
    User signup(String email, String password);

    Pair<User, MultiValueMap<String, String>> login(String email, String password);

    void logout(String email) throws IllegalArgumentException;

    boolean validateToken(String token, Long userId) throws IllegalArgumentException;
}
