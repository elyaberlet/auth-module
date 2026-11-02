package com.innowise.authservice.exception;

import com.innowise.authservice.dto.response.ApiErrorResponse;
import com.innowise.authservice.exception.handler.GlobalExceptionHandler;
import io.jsonwebtoken.MalformedJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.context.request.ServletWebRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler();
    }

    @Test
    void handleInvalidCredentials_shouldReturnUnauthorized() {
        InvalidCredentialsException exception = mock(InvalidCredentialsException.class);
        when(exception.getMessage()).thenReturn("Wrong username or password");

        var response = handler.handleInvalidCredentials(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(401);
        assertThat(response.getBody().error()).isEqualTo("Invalid credentials");
        assertThat(response.getBody().message()).isEqualTo("Wrong username or password");
        assertThat(response.getBody().validationErrors()).isNull();
    }

    @Test
    void handleJwtException_shouldReturnUnauthorized() {
        MalformedJwtException exception = new MalformedJwtException("Invalid JWT");

        var response = handler.handleJwtException(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(401);
        assertThat(response.getBody().error()).isEqualTo("Invalid token");
        assertThat(response.getBody().message())
                .isEqualTo("The provided JWT is invalid or expired");
    }

    @Test
    void handleUsernameAlreadyExists_shouldReturnConflict() {
        UsernameAlreadyExistsException exception = mock(UsernameAlreadyExistsException.class);
        when(exception.getMessage()).thenReturn("Username is already taken");

        var response = handler.handleUsernameAlreadyExists(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(409);
        assertThat(response.getBody().error()).isEqualTo("Username already exists");
        assertThat(response.getBody().message()).isEqualTo("Username is already taken");
    }

    @Test
    void handleDataIntegrityViolation_shouldReturnConflict() {
        DataIntegrityViolationException exception =
                new DataIntegrityViolationException("Unique constraint violation");

        var response = handler.handleDataIntegrityViolation(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(409);
        assertThat(response.getBody().error()).isEqualTo("Data conflict");
        assertThat(response.getBody().message())
                .isEqualTo("The request conflicts with existing data");
    }

    @Test
    void handleMethodArgumentNotValid_shouldReturnValidationErrors() throws Exception {
        BeanPropertyBindingResult bindingResult =
                new BeanPropertyBindingResult(new Object(), "request");

        bindingResult.addError(
                new FieldError("request", "username", "Username must not be blank")
        );
        bindingResult.addError(
                new FieldError("request", "email", "Email must be valid")
        );

        MethodArgumentNotValidException exception =
                new MethodArgumentNotValidException(null, bindingResult);

        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        ServletWebRequest webRequest = new ServletWebRequest(servletRequest);

        var response = handler.handleException(exception, webRequest);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isInstanceOf(ApiErrorResponse.class);

        ApiErrorResponse body = (ApiErrorResponse) response.getBody();

        assertThat(body.status()).isEqualTo(400);
        assertThat(body.error()).isEqualTo("Validation failed");
        assertThat(body.message())
                .isEqualTo("One or more fields contain invalid values");
        assertThat(body.validationErrors())
                .containsEntry("username", "Username must not be blank")
                .containsEntry("email", "Email must be valid");
    }

    @Test
    void handleUnexpectedException_shouldReturnInternalServerError() {
        Exception exception = new RuntimeException("Unexpected error");

        var response = handler.handleUnexpectedException(exception);

        assertThat(response.getStatusCode())
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(500);
        assertThat(response.getBody().error()).isEqualTo("Internal server error");
        assertThat(response.getBody().message())
                .isEqualTo("An unexpected error occurred");
    }
}