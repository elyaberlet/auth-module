package com.marketplace.authservice.controller;

import com.marketplace.authservice.dto.response.JwkKeyResponse;
import com.marketplace.authservice.dto.response.JwkSetResponse;
import com.marketplace.authservice.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwksControllerTest {

    private JwtService jwtService;
    private JwksController jwksController;
    private RSAPublicKey publicKey;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();

        jwtService = mock(JwtService.class);
        when(jwtService.getPublicKey()).thenReturn(publicKey);

        jwksController = new JwksController(jwtService);
    }

    @Test
    void getJwksShouldReturnCorrectKeyMetadata() {
        JwkSetResponse response = jwksController.getJwks();

        assertNotNull(response);
        assertNotNull(response.keys());
        assertEquals(1, response.keys().size());

        JwkKeyResponse key = response.keys().get(0);

        assertEquals("RSA", key.kty());
        assertEquals("sig", key.use());
        assertEquals("RS256", key.alg());
        assertEquals("auth-service-key-1", key.kid());
    }

    @Test
    void getJwksShouldReturnCorrectPublicKeyParameters() {
        JwkSetResponse response = jwksController.getJwks();
        JwkKeyResponse key = response.keys().get(0);

        assertEquals(
                encodeUnsigned(publicKey.getModulus().toByteArray()),
                key.n()
        );

        assertEquals(
                encodeUnsigned(publicKey.getPublicExponent().toByteArray()),
                key.e()
        );
    }

    private String encodeUnsigned(byte[] bytes) {
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }
}
