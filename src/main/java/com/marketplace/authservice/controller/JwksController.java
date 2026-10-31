package com.marketplace.authservice.controller;

import com.marketplace.authservice.dto.response.JwkKeyResponse;
import com.marketplace.authservice.dto.response.JwkSetResponse;
import com.marketplace.authservice.service.JwtService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;

@RestController
public class JwksController {

    private final JwtService jwtService;

    public JwksController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @GetMapping("/.well-known/jwks.json")
    public JwkSetResponse getJwks() {
        RSAPublicKey publicKey = jwtService.getPublicKey();

        JwkKeyResponse key = new JwkKeyResponse(
                "RSA",
                "sig",
                "RS256",
                "auth-service-key-1",
                encodeUnsigned(publicKey.getModulus()),
                encodeUnsigned(publicKey.getPublicExponent())
        );

        return new JwkSetResponse(List.of(key));
    }

    private String encodeUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();

        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = java.util.Arrays.copyOfRange(
                    bytes, 1, bytes.length
            );
        }

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }
}