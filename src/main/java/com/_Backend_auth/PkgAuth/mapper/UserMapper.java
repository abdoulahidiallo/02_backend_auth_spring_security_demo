package com._Backend_auth.PkgAuth.mapper;

import com._Backend_auth.PkgAuth.dto.response.UserResponse;
import com._Backend_auth.PkgAuth.entity.UserEntity;

public class UserMapper {

    public UserResponse toDTO(UserEntity userEntity) {
        UserResponse dto = new UserResponse();
        dto.setId(Long.valueOf(userEntity.getId()));
        dto.setEmail(userEntity.getEmail());
        return dto;
    }
}