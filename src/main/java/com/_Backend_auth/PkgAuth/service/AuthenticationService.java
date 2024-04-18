package com._Backend_auth.PkgAuth.service;

import com._Backend_auth.PkgAuth.dto.request.AuthenticationRequest;
import com._Backend_auth.PkgAuth.dto.request.RegisterRequest;
import com._Backend_auth.PkgAuth.dto.response.AuthenticationResponse;

public interface AuthenticationService {
    AuthenticationResponse register(RegisterRequest request);

    AuthenticationResponse authenticate(AuthenticationRequest request);

}
