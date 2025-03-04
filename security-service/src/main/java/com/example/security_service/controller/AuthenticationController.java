package com.example.security_service.controller;


import com.example.security_service.aggregates.request.SignInRequest;
import com.example.security_service.aggregates.request.SignUpRequest;
import com.example.security_service.aggregates.response.SignInResponse;
import com.example.security_service.entity.Usuario;
import com.example.security_service.service.AuthenticationService;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Key;
import java.util.Base64;
import java.util.List;

@RefreshScope
@RestController
@RequestMapping("/api/authentication/v1/")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Value("${dato.propiedad}")
    private  String valorPropiedad;

    @PostMapping("/signupuser")
    public ResponseEntity<Usuario> signUpUser(@RequestBody SignUpRequest signUpRequest){
        return ResponseEntity.ok(authenticationService.signUpUser(signUpRequest));
    }
    @PostMapping("/signupadmin")
    public ResponseEntity<Usuario> signUpUAdmin(@RequestBody SignUpRequest signUpRequest){

        return ResponseEntity.ok(authenticationService.signUpAdmin(signUpRequest));
    }
    @GetMapping("/all")
    public ResponseEntity<List<Usuario>> getAll(){
        return ResponseEntity.ok(authenticationService.todos());
    }
    @GetMapping("/clave")
    public ResponseEntity<String> getClave(){
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
        String dato = Base64.getEncoder().encodeToString(key.getEncoded());
        return ResponseEntity.ok(dato);
    }

    @PostMapping("/signin")
    public ResponseEntity<SignInResponse> signIn(
            @RequestBody SignInRequest signInRequest){
        return ResponseEntity.ok(authenticationService.signIn(signInRequest));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<SignInResponse> refreshToken(
            @RequestParam String refreshToken) throws IllegalAccessException {
        return ResponseEntity.ok(authenticationService.getTokenByRefreshToken(refreshToken));
    }
    @GetMapping("/prueba")
    public ResponseEntity<String> getPrueba(){
        return ResponseEntity.ok(valorPropiedad);
    }

}
