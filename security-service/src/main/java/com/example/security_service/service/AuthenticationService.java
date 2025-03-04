package com.example.security_service.service;

import com.example.security_service.aggregates.request.SignInRequest;
import com.example.security_service.aggregates.request.SignUpRequest;
import com.example.security_service.aggregates.response.SignInResponse;
import com.example.security_service.entity.Usuario;

import java.util.List;

public interface AuthenticationService {

    Usuario signUpUser(SignUpRequest signUpRequest);

    Usuario signUpAdmin(SignUpRequest signUpRequest);

    List<Usuario> todos();

    SignInResponse signIn(SignInRequest signInRequest);

    SignInResponse getTokenByRefreshToken(String refreshToken) throws IllegalAccessException;
}
