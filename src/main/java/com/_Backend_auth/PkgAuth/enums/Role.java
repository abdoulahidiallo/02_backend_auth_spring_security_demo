package com._Backend_auth.PkgAuth.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com._Backend_auth.PkgAuth.enums.Privilege.*;

@RequiredArgsConstructor
public enum Role {
    /**
     * Rôle d'administrateur, avec tous les privilèges.
     */
    ADMIN(
            Set.of(READ_PRIVILEGE, WRITE_PRIVILEGE, UPDATE_PRIVILEGE, DELETE_PRIVILEGE)
    ),
    /**
     * Rôle d'utilisateur standard, avec les privilèges de lecture et d'écriture.
     */
    USER(
            Set.of(READ_PRIVILEGE, WRITE_PRIVILEGE)
    );

    @Getter
    private final Set<Privilege> privileges;

    /**
     * Retourne la liste des autorisations (rôles et privilèges) associées à ce rôle.
     *
     * @return Une liste d'autorisations
     */
    public List<SimpleGrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = getPrivileges()
                .stream()
                .map(privilege -> new SimpleGrantedAuthority(privilege.name()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
