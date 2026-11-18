package com.innowise.authservice.controller;

import com.innowise.authservice.dto.request.CreateCredentialRequest;
import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshTokenRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.dto.response.TokenResponse;
import com.innowise.authservice.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody CreateCredentialRequest request
    ) {
        RegisterResponse response = authService.register(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @Valid @RequestBody LoginRequest request
    ) {
        TokenResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        TokenResponse response = authService.refresh(request);
        return ResponseEntity.ok(response);
    }
}