package com.marketplace.authservice.service;

import com.marketplace.authservice.entity.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

@Service
public class JwtService {

    private static final String KEY_ID = "auth-service-key-1";

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final long accessTokenExpiration;
    private final long refreshTokenExpiration;

    public JwtService(
            @Value("${auth.jwt.private-key-path}") String privateKeyPath,
            @Value("${auth.jwt.public-key-path}") String publicKeyPath,
            @Value("${auth.jwt.access-token-expiration}") long accessTokenExpiration,
            @Value("${auth.jwt.refresh-token-expiration}") long refreshTokenExpiration
    ) {
        try {
            this.privateKey = loadPrivateKey(privateKeyPath);
            this.publicKey = loadPublicKey(publicKeyPath);
            verifyKeyPair(this.privateKey, this.publicKey);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Could not load or verify JWT RSA keys", e
            );
        }

        if (accessTokenExpiration <= 0 || refreshTokenExpiration <= 0) {
            throw new IllegalArgumentException(
                    "JWT token expiration values must be positive"
            );
        }

        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    private RSAPrivateKey loadPrivateKey(String filePath)
            throws IOException, GeneralSecurityException {

        String pem = Files.readString(Path.of(filePath));

        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(base64);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return (RSAPrivateKey) keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(keyBytes)
        );
    }

    private RSAPublicKey loadPublicKey(String filePath)
            throws IOException, GeneralSecurityException {

        String pem = Files.readString(Path.of(filePath));

        String base64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(base64);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return (RSAPublicKey) keyFactory.generatePublic(
                new X509EncodedKeySpec(keyBytes)
        );
    }

    private void verifyKeyPair(
            RSAPrivateKey privateKey,
            RSAPublicKey publicKey
    ) throws GeneralSecurityException {

        byte[] testData = "jwt-key-pair-check".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(testData);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(testData);

        if (!verifier.verify(signature)) {
            throw new GeneralSecurityException(
                    "JWT public and private keys do not match"
            );
        }
    }

    public String generateAccessToken(Long userId, Role role) {
        return generateToken(
                userId, role, "access", accessTokenExpiration
        );
    }

    public String generateRefreshToken(Long userId, Role role) {
        return generateToken(
                userId, role, "refresh", refreshTokenExpiration
        );
    }

    private String generateToken(
            Long userId,
            Role role,
            String tokenType,
            long expiration
    ) {
        if (userId == null || userId <= 0) {
            throw new IllegalArgumentException("User ID must be positive");
        }

        if (role == null) {
            throw new IllegalArgumentException("Role must not be null");
        }

        Instant now = Instant.now();

        return Jwts.builder()
                .header()
                .keyId(KEY_ID)
                .and()
                .claim("user_id", userId)
                .claim("role", role.name())
                .claim("token_type", tokenType)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expiration)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    private Claims validateTokenClaims(String token, String expectedType) {
        if (token == null || token.isBlank()) {
            throw new JwtException("Token must not be empty");
        }

        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        if (!expectedType.equals(claims.get("token_type", String.class))) {
            throw new JwtException("Unexpected token type");
        }

        Object userIdClaim = claims.get("user_id");

        if (!(userIdClaim instanceof Number userIdNumber)
                || userIdNumber.longValue() <= 0) {
            throw new JwtException("Invalid user ID claim");
        }

        String roleValue = claims.get("role", String.class);

        try {
            if (roleValue == null) {
                throw new IllegalArgumentException("Role claim is missing");
            }

            Role.valueOf(roleValue);
        } catch (IllegalArgumentException exception) {
            throw new JwtException("Invalid role claim", exception);
        }

        return claims;
    }

    public Claims validateRefreshToken(String token) {
        return validateTokenClaims(token, "refresh");
    }

    public Claims validateAccessToken(String token) {
        return validateTokenClaims(token, "access");
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }
}
