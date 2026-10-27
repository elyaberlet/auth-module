package com.marketplace.authservice.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.OffsetDateTime;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomAccessDeniedHandlerTest {

    private CustomAccessDeniedHandler handler;
    private ObjectMapper objectMapper;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private ByteArrayOutputStream outputStream;

    @BeforeEach
    void setUp() throws IOException {
        objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        handler = new CustomAccessDeniedHandler(objectMapper);

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        outputStream = new ByteArrayOutputStream();

        when(response.getOutputStream()).thenReturn(
                new ServletOutputStream() {
                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setWriteListener(WriteListener writeListener) {
                    }

                    @Override
                    public void write(int b) {
                        outputStream.write(b);
                    }
                }
        );
    }

    @Test
    void handleShouldReturnForbiddenStatus() throws IOException {
        handler.handle(
                request,
                response,
                new AccessDeniedException("Sensitive internal details")
        );

        verify(response).setStatus(HttpStatus.FORBIDDEN.value());
    }

    @Test
    void handleShouldReturnJsonContentTypeAndUtf8() throws IOException {
        handler.handle(
                request,
                response,
                new AccessDeniedException("Access denied")
        );

        verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(response).setCharacterEncoding("UTF-8");
    }

    @Test
    void handleShouldReturnExpectedJsonBody() throws IOException {
        handler.handle(
                request,
                response,
                new AccessDeniedException("Access denied")
        );

        JsonNode body = objectMapper.readTree(outputStream.toByteArray());

        assertEquals(403, body.get("status").asInt());
        assertEquals("Forbidden", body.get("error").asText());
        assertEquals(
                "You do not have permission to access this resource",
                body.get("message").asText()
        );
        assertTrue(body.hasNonNull("timestamp"));
    }

    @Test
    void handleShouldReturnParseableTimestamp() throws IOException {
        handler.handle(
                request,
                response,
                new AccessDeniedException("Access denied")
        );

        JsonNode body = objectMapper.readTree(outputStream.toByteArray());

        assertDoesNotThrow(
                () -> OffsetDateTime.parse(body.get("timestamp").asText())
        );
    }

    @Test
    void handleShouldNotExposeInternalExceptionDetails() throws IOException {
        String internalMessage = "Sensitive internal details";

        handler.handle(
                request,
                response,
                new AccessDeniedException(internalMessage)
        );

        JsonNode body = objectMapper.readTree(outputStream.toByteArray());

        assertFalse(body.toString().contains(internalMessage));
        assertEquals(
                "You do not have permission to access this resource",
                body.get("message").asText()
        );
    }
}
