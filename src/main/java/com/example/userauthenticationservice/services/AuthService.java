package com.example.userauthenticationservice.services;

import com.example.userauthenticationservice.clients.KafkaProducerClient;
import com.example.userauthenticationservice.dtos.MessageDto;
import com.example.userauthenticationservice.models.Session;
import com.example.userauthenticationservice.models.SessionStatus;
import com.example.userauthenticationservice.models.User;
import com.example.userauthenticationservice.repositories.SessionRepository;
import com.example.userauthenticationservice.repositories.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
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

    private final SecretKey secretKey;

    private KafkaProducerClient kafkaProducerClient;

    private ObjectMapper objectMapper;

    public AuthService(
            UserRepository userRepository,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            SessionRepository sessionRepository,
            SecretKey secretKey,
            KafkaProducerClient kafkaProducerClient,
            ObjectMapper objectMapper
    ) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.sessionRepository = sessionRepository;
        this.secretKey = secretKey;
        this.kafkaProducerClient = kafkaProducerClient;
        this.objectMapper = objectMapper;
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

        //send email
        MessageDto messageDto = new MessageDto();
        messageDto.setTo(email);
        messageDto.setFrom("gautamsharan.scaler@gmail.com");
        messageDto.setSubject("Welcome to project");
        messageDto.setBody("Hope you are doing well!!");
        try {
            kafkaProducerClient.sendMessage("signup", objectMapper.writeValueAsString(messageDto));
        } catch (JsonProcessingException e) {
            System.out.println(e.getMessage());
            throw new RuntimeException(e);
        }

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
        jwtData.put("iat", now);
        // 10 mins
        jwtData.put("exp", now + 1000 * 60 * 10);

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

    @Override
    public void logout(String email) throws IllegalArgumentException {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            throw new IllegalArgumentException("User not found");
        }

        User user = userOptional.get();
        Optional<Session> sessionOptional = sessionRepository.findByUserId(user.getId());

        if (sessionOptional.isEmpty()) {
            throw new IllegalArgumentException("Session not found");
        }

        Session session = sessionOptional.get();
        session.setSessionStatus(SessionStatus.EXPIRED);
        sessionRepository.save(session);
    }

    @Override
    public boolean validateToken(String token, Long userId) {
        Optional<Session> optionalSession = sessionRepository.findByUserId(userId);
        if (optionalSession.isEmpty()) {
            return false;
        }

        JwtParser jwtParser = Jwts.parser().verifyWith(secretKey).build();
        Claims claims = jwtParser.parseSignedClaims(token).getPayload();

        Long expiryInEpoch = (Long)claims.get("exp");
        long currentTimeInEpoch = System.currentTimeMillis();
        System.out.println("current Time " + currentTimeInEpoch);
        System.out.println("token expiry " + expiryInEpoch);

        if (currentTimeInEpoch > expiryInEpoch) {
            Session session = optionalSession.get();
            session.setSessionStatus(SessionStatus.EXPIRED);
            sessionRepository.save(session);
            return false;
        }

        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isEmpty()) {
            return false;
        }
        User user = userOptional.get();
        String userEmail = user.getEmail();

        if (!userEmail.equals(claims.get("email"))) {
            System.out.println("user email " + userEmail);
            System.out.println("email in claims " + claims.get("email"));
            return false;
        }

        return true;
    }
}
