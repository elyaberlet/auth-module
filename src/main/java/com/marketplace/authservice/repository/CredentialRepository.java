package com.marketplace.authservice.repository;

import com.marketplace.authservice.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, Long> {
    Optional<Credential> findByUsername(String username);

    boolean existsByUsername(String username);

    Optional<Credential> findByUserId(Long userId);
}
