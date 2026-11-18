package com.innowise.authservice.controller;

import com.innowise.authservice.dto.response.JwkSetResponse;
import com.innowise.authservice.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JwksController {

    private final JwtService jwtService;

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<JwkSetResponse> getJwks() {
        return ResponseEntity.ok(jwtService.getJwkSet());
    }
}