package com.marketplace.authservice.service;

import com.marketplace.authservice.entity.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    @TempDir
    Path tempDir;

    private JwtService jwtService;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();

        privateKey = (RSAPrivateKey) keyPair.getPrivate();
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
    }

    @Test
    void generateAccessTokenShouldContainExpectedClaimsAndKid() {
        String token = jwtService.generateAccessToken(123L, Role.USER);

        Claims claims = jwtService.validateAccessToken(token);

        assertEquals(123L, claims.get("user_id", Long.class));
        assertEquals("USER", claims.get("role", String.class));
        assertEquals("access", claims.get("token_type", String.class));

        assertEquals(
                "auth-service-key-1",
                Jwts.parser()
                        .verifyWith(publicKey)
                        .build()
                        .parseSignedClaims(token)
                        .getHeader()
                        .getKeyId()
        );
    }

    @Test
    void generateRefreshTokenShouldContainRefreshType() {
        String token = jwtService.generateRefreshToken(456L, Role.ADMIN);

        Claims claims = jwtService.validateRefreshToken(token);

        assertEquals(456L, claims.get("user_id", Long.class));
        assertEquals("ADMIN", claims.get("role", String.class));
        assertEquals("refresh", claims.get("token_type", String.class));
    }

    @Test
    void accessTokenShouldNotBeAcceptedAsRefreshToken() {
        String accessToken =
                jwtService.generateAccessToken(123L, Role.USER);

        assertThrows(
                io.jsonwebtoken.JwtException.class,
                () -> jwtService.validateRefreshToken(accessToken)
        );
    }

    @Test
    void refreshTokenShouldNotBeAcceptedAsAccessToken() {
        String refreshToken =
                jwtService.generateRefreshToken(123L, Role.USER);

        assertThrows(
                io.jsonwebtoken.JwtException.class,
                () -> jwtService.validateAccessToken(refreshToken)
        );
    }

    @Test
    void tokenSignedWithAnotherKeyShouldBeRejected() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair anotherKeyPair = generator.generateKeyPair();

        String tokenSignedByAnotherKey = Jwts.builder()
                .claim("user_id", 123L)
                .claim("role", "USER")
                .claim("token_type", "access")
                .issuedAt(new java.util.Date())
                .expiration(new java.util.Date(
                        System.currentTimeMillis() + 60_000
                ))
                .signWith(anotherKeyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertThrows(
                io.jsonwebtoken.JwtException.class,
                () -> jwtService.validateAccessToken(tokenSignedByAnotherKey)
        );
    }

    @Test
    void constructorShouldRejectNonPositiveExpiration() {
        Path privateKeyPath = tempDir.resolve("private.pem");
        Path publicKeyPath = tempDir.resolve("public.pem");

        assertThrows(
                IllegalArgumentException.class,
                () -> new JwtService(
                        privateKeyPath.toString(),
                        publicKeyPath.toString(),
                        0,
                        60_000
                )
        );
    }

    private String toPem(String type, byte[] encoded) {
        String base64 = Base64.getMimeEncoder(
                64,
                "\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)
        ).encodeToString(encoded);

        return "-----BEGIN " + type + "-----\n"
                + base64
                + "\n-----END " + type + "-----\n";
    }
}
