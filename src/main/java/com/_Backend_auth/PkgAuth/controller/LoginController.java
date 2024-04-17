package com._Backend_auth.PkgAuth.controller;

import com._Backend_auth.PkgAuth.dto.LoginRequest;
import com._Backend_auth.PkgAuth.dto.LoginResponse;
import com._Backend_auth.PkgAuth.services.jwt.UserServiceIMPL;
import com._Backend_auth.PkgAuth.utils.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@CrossOrigin("*")
@RestController
@RequestMapping("/login")
public class LoginController {
    private final AuthenticationManager authenticationManager;

    private final UserServiceIMPL userServiceIMPL;

    private final JwtUtil jwtUtil;


    @Autowired
    public LoginController(AuthenticationManager authenticationManager, UserServiceIMPL userServiceIMPL, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userServiceIMPL = userServiceIMPL;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping
    public LoginResponse login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) throws IOException {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Incorrect email or password.");
        } catch (DisabledException disabledException) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Customer is not activated");
            return null;
        }
        final UserDetails userDetails = userServiceIMPL.loadUserByUsername(loginRequest.getEmail());
        final String jwt = jwtUtil.generateToken(userDetails.getUsername());

        return new LoginResponse(jwt);
    }
}
