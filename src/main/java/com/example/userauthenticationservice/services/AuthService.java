package com.example.userauthenticationservice.services;

import com.example.userauthenticationservice.models.Session;
import com.example.userauthenticationservice.models.SessionStatus;
import com.example.userauthenticationservice.models.User;
import com.example.userauthenticationservice.repositories.SessionRepository;
import com.example.userauthenticationservice.repositories.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;


@Service
public class AuthService implements IAuthService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final SessionRepository sessionRepository;

    public AuthService(
            UserRepository userRepository,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            SessionRepository sessionRepository) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.sessionRepository = sessionRepository;
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
    public Pair<User, MultiValueMap<String, String>> login(String email, String password) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            return null;
        }

        User user = userOptional.get();

        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            return null;
        }

        Map<String, Object> jwtData = new HashMap<>();
        jwtData.put("email", user.getEmail());
        jwtData.put("role", user.getRoles());
        long now = System.currentTimeMillis();
        jwtData.put("iat", new Date(now));
        jwtData.put("exp", new Date(now + 1000 * 60 * 2));

        MacAlgorithm algorithm = Jwts.SIG.HS256;
        SecretKey secretKey = algorithm.key().build();
        String token = Jwts.builder().claims(jwtData).signWith(secretKey).compact();

        Session session = new Session();
        session.setUser(userOptional.get());
        session.setSessionStatus(SessionStatus.ACTIVE);
        session.setToken(token);
        sessionRepository.save(session);

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.SET_COOKIE, token);

        return new Pair<>(user, headers);
    }
}
