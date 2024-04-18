package com._Backend_auth.PkgAuth.entity;

import com._Backend_auth.PkgAuth.enums.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@Table(name = "users")
public class UserEntity implements UserDetails {

    @Id
    @GeneratedValue
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    /**
     * Retourne les autorisations (rôles) associées à l'utilisateur.
     *
     * @return Une collection d'autorisations
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return role.getAuthorities();
    }

    /**
     * Retourne le mot de passe de l'utilisateur.
     *
     * @return Le mot de passe de l'utilisateur
     */
    @Override
    public String getPassword() {
        return password;
    }

    /**
     * Retourne le nom d'utilisateur (email) de l'utilisateur.
     *
     * @return Le nom d'utilisateur de l'utilisateur
     */
    @Override
    public String getUsername() {
        return email;
    }

    /**
     * Indique si le compte de l'utilisateur n'est pas expiré.
     *
     * @return Toujours true, car le compte n'expire pas
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indique si le compte de l'utilisateur n'est pas verrouillé.
     *
     * @return Toujours true, car le compte n'est pas verrouillé
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Indique si les informations d'identification de l'utilisateur ne sont pas expirées.
     *
     * @return Toujours true, car les informations d'identification ne sont pas expirées
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Indique si le compte de l'utilisateur est activé.
     *
     * @return Toujours true, car le compte est activé
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
