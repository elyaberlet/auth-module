package com.marketplace.authservice.controller;

import com.marketplace.authservice.dto.request.CreateCredentialRequest;
import com.marketplace.authservice.dto.request.LoginRequest;
import com.marketplace.authservice.dto.request.RefreshTokenRequest;
import com.marketplace.authservice.dto.request.ValidateTokenRequest;
import com.marketplace.authservice.dto.response.RegisterResponse;
import com.marketplace.authservice.dto.response.TokenResponse;
import com.marketplace.authservice.dto.response.ValidateTokenResponse;
import com.marketplace.authservice.service.AuthService;
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

    @PostMapping("/credentials")
    public ResponseEntity<RegisterResponse> createCredential(
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

    @PostMapping("/validate")
    public ResponseEntity<ValidateTokenResponse> validate(
            @Valid @RequestBody ValidateTokenRequest request
    ) {
        return ResponseEntity.ok(authService.validateToken(request));
    }
}