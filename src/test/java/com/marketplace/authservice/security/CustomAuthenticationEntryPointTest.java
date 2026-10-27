package com.marketplace.authservice.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import java.time.OffsetDateTime;

import static org.junit.jupiter.api.Assertions.*;

class CustomAuthenticationEntryPointTest {

    private ObjectMapper objectMapper;
    private CustomAuthenticationEntryPoint entryPoint;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        entryPoint = new CustomAuthenticationEntryPoint(objectMapper);

        request = new MockHttpServletRequest();
        request.setRequestURI("/api/users");

        response = new MockHttpServletResponse();
    }

    @Test
    void commence_shouldReturn401AndJsonErrorBody() throws Exception {
        entryPoint.commence(
                request,
                response,
                new BadCredentialsException("Invalid token")
        );

        assertEquals(
                HttpServletResponse.SC_UNAUTHORIZED,
                response.getStatus()
        );
        assertTrue(
                response.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)
        );
        assertEquals("UTF-8", response.getCharacterEncoding());

        JsonNode body = objectMapper.readTree(response.getContentAsString());

        assertEquals(401, body.get("status").asInt());
        assertEquals("Unauthorized", body.get("error").asText());
        assertEquals(
                "Authentication is required or the token is invalid",
                body.get("message").asText()
        );

        assertTrue(body.hasNonNull("timestamp"));

        assertDoesNotThrow(
                () -> OffsetDateTime.parse(body.get("timestamp").asText())
        );
    }

    @Test
    void commence_shouldReturnSameErrorRegardlessOfExceptionMessage()
            throws Exception {
        entryPoint.commence(
                request,
                response,
                new BadCredentialsException("Some internal detail")
        );

        JsonNode body = objectMapper.readTree(response.getContentAsString());

        assertEquals(
                "Authentication is required or the token is invalid",
                body.get("message").asText()
        );
        assertFalse(
                body.get("message").asText().contains("Some internal detail")
        );
    }
}
