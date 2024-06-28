package com.example.userauthenticationservice.repositories;

import com.example.userauthenticationservice.models.Session;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<Session, Long> {
}
