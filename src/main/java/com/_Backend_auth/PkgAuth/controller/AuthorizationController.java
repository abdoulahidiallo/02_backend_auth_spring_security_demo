package com._Backend_auth.PkgAuth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
@PreAuthorize("hasAnyRole('ADMIN','USER')")
@Tag(name = "Authorization", description = "L'API d'autorisation. Contient une méthode hello sécurisée")
public class AuthorizationController {

    /**
     * Endpoint sécurisé qui nécessite un rôle ADMIN et l'autorité READ_PRIVILEGE.
     *
     * @return Une réponse HTTP 200 OK avec un message de bienvenue
     */
    @GetMapping("/admin/resource")
    @PreAuthorize("hasAuthority('READ_PRIVILEGE') and hasRole('ADMIN')")
    @Operation(
            description = "Cet endpoint nécessite un JWT valide, le rôle ADMIN et l'autorité READ_PRIVILEGE",
            summary = "Endpoint hello sécurisé",
            responses = {
                    @ApiResponse(
                            description = "Succès",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Non autorisé / Jeton invalide",
                            responseCode = "401"
                    )
            }
    )
    public ResponseEntity<String> sayHelloWithRoleAdminAndReadAuthority() {
        return ResponseEntity.ok("Bonjour, vous avez accès à une ressource protégée qui nécessite le rôle admin et l'autorité de lecture.");
    }

    /**
     * Endpoint sécurisé qui nécessite un rôle ADMIN et l'autorité DELETE_PRIVILEGE.
     *
     * @return Une réponse HTTP 200 OK avec un message de bienvenue
     */
    @DeleteMapping("/admin/resource")
    @PreAuthorize("hasAuthority('DELETE_PRIVILEGE') and hasRole('ADMIN')")
    @Operation(
            description = "Cet endpoint nécessite un JWT valide, le rôle ADMIN et l'autorité DELETE_PRIVILEGE",
            summary = "Endpoint de suppression sécurisé",
            responses = {
                    @ApiResponse(
                            description = "Succès",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Non autorisé / Jeton invalide",
                            responseCode = "401"
                    )
            }
    )
    public ResponseEntity<String> sayHelloWithRoleAdminAndDeleteAuthority() {
        return ResponseEntity.ok("Bonjour, vous avez accès à une ressource protégée qui nécessite le rôle admin et l'autorité de suppression.");
    }

    /**
     * Endpoint sécurisé qui nécessite un rôle ADMIN ou USER et l'autorité WRITE_PRIVILEGE.
     *
     * @return Une réponse HTTP 200 OK avec un message de bienvenue
     */
    @PostMapping("/user/resource")
    @PreAuthorize("hasAuthority('WRITE_PRIVILEGE') and hasAnyRole('ADMIN','USER')")
    @Operation(
            description = "Cet endpoint nécessite un JWT valide, le rôle ADMIN ou USER et l'autorité WRITE_PRIVILEGE",
            summary = "Endpoint de création sécurisé",
            responses = {
                    @ApiResponse(
                            description = "Succès",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Non autorisé / Jeton invalide",
                            responseCode = "401"
                    )
            }
    )
    public ResponseEntity<String> sayHelloWithRoleUserAndCreateAuthority() {
        return ResponseEntity.ok("Bonjour, vous avez accès à une ressource protégée qui nécessite le rôle utilisateur et l'autorité d'écriture.");
    }

    /**
     * Endpoint sécurisé qui nécessite un rôle ADMIN ou USER et l'autorité UPDATE_PRIVILEGE.
     *
     * @return Une réponse HTTP 200 OK avec un message de bienvenue
     */
    @PutMapping("/user/resource")
    @PreAuthorize("hasAuthority('UPDATE_PRIVILEGE') and hasAnyRole('ADMIN','USER')")
    @Operation(
            description = "Cet endpoint nécessite un JWT valide, le rôle ADMIN ou USER et l'autorité UPDATE_PRIVILEGE",
            summary = "Endpoint de mise à jour sécurisé",
            responses = {
                    @ApiResponse(
                            description = "Succès",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Non autorisé / Jeton invalide",
                            responseCode = "401"
                    )
            }
    )
    public ResponseEntity<String> sayHelloWithRoleUserAndUpdateAuthority() {
        return ResponseEntity.ok("Bonjour, vous avez accès à une ressource protégée qui nécessite le rôle utilisateur et l'autorité de mise à jour.");
    }
}
