package com.example.userauthenticationservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SpringSecurity {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.cors().disable();
        http.csrf().disable();
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());
        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder bcryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
