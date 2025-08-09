package com.appsdeveloperblog.photoapp.api.users.security;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import com.appsdeveloperblog.photoapp.api.users.service.UsersService;
import com.appsdeveloperblog.photoapp.api.users.shared.UserDto;
import com.appsdeveloperblog.photoapp.api.users.ui.model.LoginRequestModel;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    Environment environment;
    UsersService userService;

    public AuthenticationFilter(AuthenticationManager authManager, Environment environment, UsersService userService) {
        super(authManager);
        this.environment = environment;
        this.userService = userService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        try {
            LoginRequestModel creds = new ObjectMapper().readValue(request.getInputStream(), LoginRequestModel.class);

            return this.getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(creds.userName(), creds.password(), new ArrayList<>()));

        } catch (IOException e) {
            throw new AuthenticationServiceException("Invalid Login Request", e);
        }

    }
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication auth) throws IOException, ServletException {

        String userName = ((User)auth.getPrincipal()).getUsername();
        UserDto user = userService.loadUserByEmail(userName);

        String tokenSecret= environment.getProperty("token.secret");
        byte[] secretKeyBytes = Base64.getEncoder().encode(tokenSecret.getBytes()); 
        SecretKey secretKey= Keys.hmacShaKeyFor(secretKeyBytes);

        String token = Jwts.builder()
                .subject(user.getUserId())
                .expiration(Date.from(
                        Instant.now().plusMillis(Long.parseLong(environment.getProperty("token.expiration_time")))))
                .signWith(secretKey)
                .issuedAt(Date.from(Instant.now()))
                .compact();

        response.addHeader("token", token);
        response.addHeader("userId", user.getUserId());

    }

}
