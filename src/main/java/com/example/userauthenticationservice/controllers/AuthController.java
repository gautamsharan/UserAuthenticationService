package com.example.userauthenticationservice.controllers;

import com.example.userauthenticationservice.dtos.*;
import com.example.userauthenticationservice.models.User;
import com.example.userauthenticationservice.services.IAuthService;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final IAuthService authService;

    public AuthController(IAuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<UserDto> signUp(@RequestBody SignUpRequestDto signUpRequestDto) {
        User user = authService.signup(signUpRequestDto.getEmail(),
                signUpRequestDto.getPassword());
        return new ResponseEntity<>(userDtoFromUser(user), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<UserDto> login(@RequestBody LoginRequestDto loginRequestDto) {
        try {
            Pair<User, MultiValueMap<String, String>> response = authService.login(
                    loginRequestDto.getEmail(),
                    loginRequestDto.getPassword());

            User user = response.a;
            MultiValueMap<String, String> headers = response.b;

            if (user == null) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "Invalid email or password");
            }

            return new ResponseEntity<>(userDtoFromUser(user), headers, HttpStatus.OK);
        } catch (ResponseStatusException e) {
            return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/logout")
    public void logout(@RequestBody LogoutRequestDto logoutRequestDto) {

    }

    @PostMapping("/forgetPassword")
    public void forgetPassword(@RequestBody ForgetPasswordRequestDto forgetPasswordRequestDto) {

    }

    @PostMapping("/validateToken")
    public void validateToken(@RequestBody ValidateTokenRequestDto validateTokenRequestDto) {

    }

    private UserDto userDtoFromUser(User user) {
        UserDto userDto = new UserDto();
        userDto.setEmail(user.getEmail());
        userDto.setRoles(user.getRoles());
        return userDto;
    }
}
