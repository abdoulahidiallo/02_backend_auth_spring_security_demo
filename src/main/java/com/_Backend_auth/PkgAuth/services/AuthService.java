package com._Backend_auth.PkgAuth.services;

import com._Backend_auth.PkgAuth.dto.SignupRequest;
import com._Backend_auth.PkgAuth.entities.User;

public interface AuthService {
    User createUser(SignupRequest signupRequest);
}
