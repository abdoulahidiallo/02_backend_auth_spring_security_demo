package com._Backend_auth.PkgAuth.dto.response;

import com._Backend_auth.PkgAuth.entity.RefreshToken;
import lombok.Data;

import java.util.Set;
@Data
public class UserResponse {
    private Long id;
    private String email;
    private String username;
    private Set<RefreshToken> roles;

}
