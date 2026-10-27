package com.marketplace.authservice.config;

import com.marketplace.authservice.security.CustomAuthenticationEntryPoint;
import com.marketplace.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {

    private JwtService jwtService;
    private CustomAuthenticationEntryPoint authenticationEntryPoint;
    private JwtAuthenticationFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        jwtService = mock(JwtService.class);
        authenticationEntryPoint =
                mock(CustomAuthenticationEntryPoint.class);

        filter = new JwtAuthenticationFilter(
                jwtService,
                authenticationEntryPoint
        );

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        filterChain = mock(FilterChain.class);

        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_shouldContinueWhenAuthorizationHeaderIsMissing()
            throws Exception {

        when(request.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
        verifyNoInteractions(authenticationEntryPoint);
    }

    @Test
    void doFilterInternal_shouldContinueWhenHeaderIsNotBearer()
            throws Exception {

        when(request.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn("Basic some-credentials");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
        verifyNoInteractions(authenticationEntryPoint);
    }

    @Test
    void doFilterInternal_shouldAuthenticateWhenTokenIsValid()
            throws Exception {

        Claims claims = mock(Claims.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer valid-token");
        when(jwtService.validateAccessToken("valid-token"))
                .thenReturn(claims);
        when(claims.get("user_id")).thenReturn(1001L);
        when(claims.get("role")).thenReturn("USER");

        filter.doFilterInternal(request, response, filterChain);

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(authentication);
        assertEquals(1001L, authentication.getPrincipal());
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(authority ->
                        authority.getAuthority().equals("ROLE_USER")));

        verify(filterChain).doFilter(request, response);
        verify(authenticationEntryPoint, never())
                .commence(any(), any(), any());
    }

    @Test
    void doFilterInternal_shouldRejectInvalidToken() throws Exception {

        when(request.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer invalid-token");
        when(jwtService.validateAccessToken("invalid-token"))
                .thenThrow(new JwtException("Invalid token"));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(authenticationEntryPoint).commence(
                eq(request),
                eq(response),
                any()
        );
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_shouldRejectTokenWhenUserIdIsMissing()
            throws Exception {

        Claims claims = mock(Claims.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer token-without-user-id");
        when(jwtService.validateAccessToken("token-without-user-id"))
                .thenReturn(claims);
        when(claims.get("user_id")).thenReturn(null);
        when(claims.get("role")).thenReturn("USER");

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(authenticationEntryPoint).commence(
                eq(request),
                eq(response),
                any()
        );
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_shouldRejectUnknownRole() throws Exception {

        Claims claims = mock(Claims.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer token-with-unknown-role");
        when(jwtService.validateAccessToken("token-with-unknown-role"))
                .thenReturn(claims);
        when(claims.get("user_id")).thenReturn(1001L);
        when(claims.get("role")).thenReturn("UNKNOWN");

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(authenticationEntryPoint).commence(
                eq(request),
                eq(response),
                any()
        );
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_shouldAuthenticateAdminRole()
            throws Exception {

        Claims claims = mock(Claims.class);

        when(request.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn("Bearer admin-token");
        when(jwtService.validateAccessToken("admin-token"))
                .thenReturn(claims);
        when(claims.get("user_id")).thenReturn(2001L);
        when(claims.get("role")).thenReturn("ADMIN");

        filter.doFilterInternal(request, response, filterChain);

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(authentication);
        assertEquals(2001L, authentication.getPrincipal());
        assertTrue(authentication.getAuthorities().stream()
                .anyMatch(authority ->
                        authority.getAuthority().equals("ROLE_ADMIN")));

        verify(filterChain).doFilter(request, response);
        verify(authenticationEntryPoint, never())
                .commence(any(), any(), any());
    }
}
