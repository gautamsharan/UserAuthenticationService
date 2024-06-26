package com.example.userauthenticationservice.services;

import com.example.userauthenticationservice.models.User;

public interface IAuthService {
    User signup(String email, String password);

    User login(String email, String password);
}
