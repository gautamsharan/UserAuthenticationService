package com.example.userauthenticationservice.exceptions;

public class AuthenticationFailedException extends Exception {
    public AuthenticationFailedException(String message) {
        super(message);
    }
}
