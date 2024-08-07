package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.dto.JwtAuthenticationResponse;
import com.example.springsecurityjwt.dto.RefreshTokenRequest;
import com.example.springsecurityjwt.dto.SignUpRequest;
import com.example.springsecurityjwt.dto.SigninRequest;
import com.example.springsecurityjwt.entities.User;

public interface AuthenticationService {

    User signup(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signin(SigninRequest signinRequest);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
