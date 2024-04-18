package com._Backend_auth.PkgAuth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    /**
     * Utilisateur associé à ce jeton de rafraîchissement.
     */
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private UserEntity userEntity;

    /**
     * Valeur du jeton de rafraîchissement.
     */
    @Column(nullable = false, unique = true)
    private String token;

    /**
     * Date d'expiration du jeton de rafraîchissement.
     */
    @Column(nullable = false)
    private Instant expiryDate;

    /**
     * Indique si le jeton a été révoqué.
     */
    public boolean revoked;
}
