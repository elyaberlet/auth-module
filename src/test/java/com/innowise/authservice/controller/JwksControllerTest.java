package com.innowise.authservice.controller;

import com.innowise.authservice.dto.response.JwkKeyResponse;
import com.innowise.authservice.dto.response.JwkSetResponse;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.ResponseEntity;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JwksControllerTest {

    @TempDir
    Path tempDir;

    private JwtService jwtService;
    private JwksController jwksController;
    private RSAPublicKey publicKey;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();

        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();

        Path privateKeyPath = tempDir.resolve("private.pem");
        Path publicKeyPath = tempDir.resolve("public.pem");

        Files.writeString(
                privateKeyPath,
                toPem("PRIVATE KEY", privateKey.getEncoded())
        );

        Files.writeString(
                publicKeyPath,
                toPem("PUBLIC KEY", publicKey.getEncoded())
        );

        jwtService = new JwtService(
                privateKeyPath.toString(),
                publicKeyPath.toString(),
                900_000,
                604_800_000
        );

        jwksController = new JwksController(jwtService);
    }

    @Test
    void getJwksShouldReturnCorrectKeyMetadata() {
        ResponseEntity<JwkSetResponse> response =
                jwksController.getJwks();

        assertNotNull(response);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().keys());
        assertEquals(1, response.getBody().keys().size());

        JwkKeyResponse key = response.getBody().keys().get(0);

        assertEquals("RSA", key.kty());
        assertEquals("sig", key.use());
        assertEquals("RS256", key.alg());
        assertEquals("auth-service-key-1", key.kid());
        assertNotNull(key.n());
        assertNotNull(key.e());
    }

    @Test
    void jwksPublicKeyShouldVerifyRealJwtSignature() throws Exception {
        // Generate a real access token using JwtService
        String token = jwtService.generateAccessToken(123L, Role.USER);

        // Get the public key information from JWKS
        ResponseEntity<JwkSetResponse> response =
                jwksController.getJwks();

        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().keys().size());

        JwkKeyResponse jwk = response.getBody().keys().get(0);

        // Rebuild RSA public key using modulus (n) and exponent (e)
        byte[] modulusBytes = Base64.getUrlDecoder().decode(jwk.n());
        byte[] exponentBytes = Base64.getUrlDecoder().decode(jwk.e());

        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger exponent = new BigInteger(1, exponentBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPublicKey reconstructedPublicKey =
                (RSAPublicKey) keyFactory.generatePublic(
                        new RSAPublicKeySpec(modulus, exponent)
                );

        // Verify the real JWT signature using the reconstructed key
        Claims claims = Jwts.parser()
                .verifyWith(reconstructedPublicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals(123L, claims.get("user_id", Long.class));
        assertEquals("USER", claims.get("role", String.class));
        assertEquals("access", claims.get("token_type", String.class));
    }

    private String toPem(String type, byte[] encoded) {
        String base64 = Base64.getMimeEncoder(
                64,
                "\n".getBytes(StandardCharsets.UTF_8)
        ).encodeToString(encoded);

        return "-----BEGIN " + type + "-----\n"
                + base64
                + "\n-----END " + type + "-----\n";
    }
}
