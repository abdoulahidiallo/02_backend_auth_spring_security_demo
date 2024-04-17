package com._Backend_auth.PkgAuth.controller;

import com._Backend_auth.PkgAuth.dto.SignupRequest;
import com._Backend_auth.PkgAuth.entities.User;
import com._Backend_auth.PkgAuth.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@CrossOrigin("*")
@RestController
@RequestMapping("/signup")
public class SignupController {

    private final AuthService authService;

    @Autowired
    public SignupController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping
    public ResponseEntity<?> signupUser(@RequestBody SignupRequest signupRequest) {
        User createdUser = authService.createUser(signupRequest);
        if (createdUser != null) {
            return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Failed to create new user");
        }
    }

}
