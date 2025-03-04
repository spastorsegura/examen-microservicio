package com.example.security_service.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user/v1/")
public class UserController {

    @GetMapping
    public ResponseEntity<String> getSaludo(){
        return ResponseEntity.ok("Hola User!!!");
    }
}

