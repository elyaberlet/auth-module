
package com.innowise.authservice.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.dto.response.UserServiceUserResponse;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.repository.CredentialRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class AuthServiceIntegrationTest {

    private static final String USERNAME = "integration.user";
    private static final String PASSWORD = "SecurePassword123";
    private static final Long USER_ID = 123L;

    private static final Path KEY_DIRECTORY;
    private static final String PRIVATE_KEY_PATH;
    private static final String PUBLIC_KEY_PATH;

    static {
        try {
            KEY_DIRECTORY = Files.createTempDirectory("auth-test-keys");

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);

            KeyPair keyPair = generator.generateKeyPair();

            PRIVATE_KEY_PATH =
                    KEY_DIRECTORY.resolve("private.pem").toString();

            PUBLIC_KEY_PATH =
                    KEY_DIRECTORY.resolve("public.pem").toString();

            String privatePem = """
                    -----BEGIN PRIVATE KEY-----
                    %s
                    -----END PRIVATE KEY-----
                    """.formatted(
                    Base64.getMimeEncoder(
                            64,
                            "\n".getBytes(StandardCharsets.UTF_8)
                    ).encodeToString(keyPair.getPrivate().getEncoded())
            );

            String publicPem = """
                    -----BEGIN PUBLIC KEY-----
                    %s
                    -----END PUBLIC KEY-----
                    """.formatted(
                    Base64.getMimeEncoder(
                            64,
                            "\n".getBytes(StandardCharsets.UTF_8)
                    ).encodeToString(keyPair.getPublic().getEncoded())
            );

            Files.writeString(Path.of(PRIVATE_KEY_PATH), privatePem);
            Files.writeString(Path.of(PUBLIC_KEY_PATH), publicPem);

        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    @Container
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("auth_test")
                    .withUsername("test")
                    .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);

        registry.add(
                "auth.jwt.private-key-path",
                () -> PRIVATE_KEY_PATH
        );

        registry.add(
                "auth.jwt.public-key-path",
                () -> PUBLIC_KEY_PATH
        );

        registry.add("auth.jwt.access-token-expiration", () -> 900000);
        registry.add("auth.jwt.refresh-token-expiration", () -> 604800000);

        registry.add(
                "user-service.base-url",
                () -> "http://localhost:9999"
        );
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private UserServiceClient userServiceClient;

    @BeforeEach
    void setUp() {
        credentialRepository.deleteAll();

        when(userServiceClient.createUser(any()))
                .thenReturn(new UserServiceUserResponse(USER_ID));
    }

    @Test
    void registrationShouldRunLiquibaseAndStoreBcryptPassword()
            throws Exception {

        assertTrue(POSTGRES.isRunning());

        String request = """
                {
                    "name": "Ivan",
                    "surname": "Petrov",
                    "birthDate": "1998-05-15",
                    "email": "ivan@example.com",
                    "username": "%s",
                    "password": "%s"
                }
                """.formatted(USERNAME, PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.userId").value(USER_ID))
                .andExpect(jsonPath("$.username").value(USERNAME));

        Credential credential = credentialRepository
                .findByUsername(USERNAME)
                .orElseThrow();

        assertEquals(USER_ID, credential.getUserId());

        assertNotEquals(
                PASSWORD,
                credential.getPasswordHash()
        );

        assertTrue(
                passwordEncoder.matches(
                        PASSWORD,
                        credential.getPasswordHash()
                )
        );

        assertNotNull(credential.getCreatedAt());
        assertNotNull(credential.getUpdatedAt());
    }

    @Test
    void loginShouldReturnTokensForCorrectPassword() throws Exception {
        registerUser();

        String request = """
                {
                    "username": "%s",
                    "password": "%s"
                }
                """.formatted(USERNAME, PASSWORD);

        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode json = objectMapper.readTree(response);

        String accessToken = json.get("accessToken").asText();

        Claims claims = Jwts.parser()
                .verifyWith(loadPublicKey())
                .build()
                .parseSignedClaims(accessToken)
                .getPayload();

        assertEquals(USER_ID, claims.get("user_id", Long.class));
        assertEquals("USER", claims.get("role", String.class));
        assertEquals("access", claims.get("token_type", String.class));
    }

    @Test
    void loginShouldRejectIncorrectPassword() throws Exception {
        registerUser();

        String request = """
                {
                    "username": "%s",
                    "password": "WrongPassword123"
                }
                """.formatted(USERNAME);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginShouldRejectUnknownUsername() throws Exception {
        String request = """
                {
                    "username": "unknown.user",
                    "password": "SecurePassword123"
                }
                """;

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void databaseShouldRejectDuplicateUsername() {
        Credential first = createCredential(123L, "duplicate.user");
        credentialRepository.saveAndFlush(first);

        Credential second = createCredential(456L, "duplicate.user");

        assertThrows(
                DataIntegrityViolationException.class,
                () -> credentialRepository.saveAndFlush(second)
        );
    }

    @Test
    void databaseShouldRejectDuplicateUserId() {
        Credential first = createCredential(123L, "first.user");
        credentialRepository.saveAndFlush(first);

        Credential second = createCredential(123L, "second.user");

        assertThrows(
                DataIntegrityViolationException.class,
                () -> credentialRepository.saveAndFlush(second)
        );
    }

    @Test
    void jwksShouldBeAvailableWithoutAuthenticationAndVerifyRealToken()
            throws Exception {

        registerUser();

        String loginRequest = """
                {
                    "username": "%s",
                    "password": "%s"
                }
                """.formatted(USERNAME, PASSWORD);

        String loginResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequest))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String token = objectMapper.readTree(loginResponse)
                .get("accessToken")
                .asText();

        String jwksResponse = mockMvc.perform(
                        get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].kid")
                        .value("auth-service-key-1"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode jwk = objectMapper.readTree(jwksResponse)
                .get("keys")
                .get(0);

        String modulusValue = jwk.get("n").asText();
        String exponentValue = jwk.get("e").asText();

        RSAPublicKey reconstructedKey = reconstructPublicKey(
                modulusValue,
                exponentValue
        );

        Claims claims = Jwts.parser()
                .verifyWith(reconstructedKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals(USER_ID, claims.get("user_id", Long.class));
        assertEquals("USER", claims.get("role", String.class));
    }

    @Test
    void registrationAndLoginShouldBeAccessibleWithoutJwt()
            throws Exception {

        String jwksResponse = mockMvc.perform(
                        get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertFalse(jwksResponse.isBlank());

        String loginRequest = """
                {
                    "username": "missing.user",
                    "password": "SecurePassword123"
                }
                """;

        // Login is public. The 401 response is caused by unknown credentials,
        // not by missing JWT authentication.
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequest))
                .andExpect(status().isUnauthorized());
    }

    private void registerUser() throws Exception {
        String request = """
                {
                    "name": "Ivan",
                    "surname": "Petrov",
                    "birthDate": "1998-05-15",
                    "email": "ivan@example.com",
                    "username": "%s",
                    "password": "%s"
                }
                """.formatted(USERNAME, PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isCreated());
    }

    private Credential createCredential(Long userId, String username) {
        Credential credential = new Credential();
        credential.setUserId(userId);
        credential.setUsername(username);
        credential.setPasswordHash(passwordEncoder.encode(PASSWORD));
        credential.setRole(Role.USER);
        return credential;
    }

    private RSAPublicKey loadPublicKey() throws Exception {
        String pem = Files.readString(Path.of(PUBLIC_KEY_PATH));

        String base64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(base64);

        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(
                        new java.security.spec.X509EncodedKeySpec(keyBytes)
                );
    }

    private RSAPublicKey reconstructPublicKey(
            String modulus,
            String exponent
    ) throws Exception {

        byte[] modulusBytes = Base64.getUrlDecoder().decode(modulus);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(exponent);

        BigInteger n = new BigInteger(1, modulusBytes);
        BigInteger e = new BigInteger(1, exponentBytes);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);

        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(spec);
    }
}
