package com.example.security_service.service.impl;

import com.example.security_service.aggregates.constants.Constants;
import com.example.security_service.aggregates.request.SignInRequest;
import com.example.security_service.aggregates.request.SignUpRequest;
import com.example.security_service.aggregates.response.SignInResponse;
import com.example.security_service.entity.Rol;
import com.example.security_service.entity.Role;
import com.example.security_service.entity.Usuario;
import com.example.security_service.repository.RolRepository;
import com.example.security_service.repository.UsuarioRepository;
import com.example.security_service.service.AuthenticationService;
import com.example.security_service.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

@Service
@RequiredArgsConstructor
@Log4j2
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    @Override
    public Usuario signUpUser(SignUpRequest signUpRequest) {
        Usuario usuario = getUsuarioEntity(signUpRequest);
        usuario.setRoles(Collections.singleton(getRoles(Role.USER)));
        return usuarioRepository.save(usuario);
    }

    @Override
    public Usuario signUpAdmin(SignUpRequest signUpRequest) {
        Usuario usuario = getUsuarioEntity(signUpRequest);
        usuario.setRoles(Collections.singleton(getRoles(Role.ADMIN)));
        return usuarioRepository.save(usuario);
    }

    @Override
    public List<Usuario> todos() {
        return usuarioRepository.findAll();
    }

    @Override
    public SignInResponse signIn(SignInRequest signInRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                signInRequest.getEmail(),signInRequest.getPassword()));
        var user = usuarioRepository.findByEmail(signInRequest.getEmail()).orElseThrow(
                ()-> new UsernameNotFoundException("Error usuario no encontrado!!"));
        var token = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(new HashMap<>(),user);
        return SignInResponse.builder()
                .token(token)
                .refreshToken(refreshToken)
                .build();
    }


    @Override
    public SignInResponse getTokenByRefreshToken(String refreshToken) throws IllegalAccessException {

        log.info("Ejecutando - getTokenByRefreshToken");
        if(!jwtService.isRefreshToken(refreshToken)){
            throw new RuntimeException("Error el token ingresado no es un REFRESH ");
        }

        String userEmail = jwtService.extractUsername(refreshToken);


        Usuario usuario = usuarioRepository.findByEmail(userEmail).orElseThrow(
                ()-> new UsernameNotFoundException("Error usuario no encontrado"));

        if(!jwtService.validateToken(refreshToken, usuario)){
            throw new IllegalAccessException("Error el token no le pertenece a al usuario");
        }

        String newToken = jwtService.generateToken(usuario);
        return SignInResponse.builder()
                .token(newToken)
                .refreshToken(refreshToken)
                .build();
    }

    private Usuario getUsuarioEntity(SignUpRequest signUpRequest){
        return Usuario.builder()
                .nombres(signUpRequest.getNombres())
                .apellidos(signUpRequest.getApellidos())
                .email(signUpRequest.getEmail())
                .password(new BCryptPasswordEncoder().encode(signUpRequest.getPassword()))
                .tipoDoc(signUpRequest.getTipoDoc())
                .numDoc(signUpRequest.getNumDoc())
                .isAccountNonExpired(Constants.STATUS_ACTIVE)
                .isAccountNonLocked(Constants.STATUS_ACTIVE)
                .isCredentialsNonExpired(Constants.STATUS_ACTIVE)
                .isEnabled(Constants.STATUS_ACTIVE)
                .build();
    }

    private Rol getRoles(Role rolBuscado){
        return rolRepository.findByNombreRol(rolBuscado.name())
                .orElseThrow(() -> new RuntimeException("Error el rol no exixte: " + rolBuscado.name()));
    }
}