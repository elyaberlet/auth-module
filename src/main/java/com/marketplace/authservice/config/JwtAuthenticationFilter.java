package com.marketplace.authservice.config;

import com.marketplace.authservice.entity.Role;
import com.marketplace.authservice.security.CustomAuthenticationEntryPoint;
import com.marketplace.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            CustomAuthenticationEntryPoint authenticationEntryPoint) {
        this.jwtService = jwtService;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String authorizationHeader =
                request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader == null
                || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.substring(7);

        try {
            Claims claims = jwtService.validateAccessToken(token);

            Object userIdClaim = claims.get("user_id");
            Object roleClaim = claims.get("role");

            if (!(userIdClaim instanceof Number userIdNumber)
                    || roleClaim == null) {
                throw new JwtException("Required JWT claims are missing or invalid");
            }

            long userId = userIdNumber.longValue();

            if (userId <= 0) {
                throw new JwtException("Invalid user ID claim");
            }

            if (!(roleClaim instanceof String roleValue)) {
                throw new JwtException("Invalid role claim");
            }

            Role role = Role.valueOf(roleValue);

            var authorities = List.of(
                    new SimpleGrantedAuthority("ROLE_" + role.name())
            );

            var authentication = new UsernamePasswordAuthenticationToken(
                    userId,
                    null,
                    authorities
            );

            SecurityContextHolder.getContext()
                    .setAuthentication(authentication);

        } catch (JwtException | IllegalArgumentException exception) {
            SecurityContextHolder.clearContext();

            authenticationEntryPoint.commence(
                    request,
                    response,
                    new BadCredentialsException(
                            "Invalid or expired access token"
                    )
            );
            return;
        }

        filterChain.doFilter(request, response);
    }
}
