package com._Backend_auth.PkgAuth.controller;

import com._Backend_auth.PkgAuth.dto.request.AuthenticationRequest;
import com._Backend_auth.PkgAuth.dto.request.RefreshTokenRequest;
import com._Backend_auth.PkgAuth.dto.request.RegisterRequest;
import com._Backend_auth.PkgAuth.dto.response.AuthenticationResponse;
import com._Backend_auth.PkgAuth.dto.response.RefreshTokenResponse;
import com._Backend_auth.PkgAuth.service.AuthenticationService;
import com._Backend_auth.PkgAuth.service.JwtService;
import com._Backend_auth.PkgAuth.service.RefreshTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Authentication", description = "L'API d'authentification. Contient les opérations de connexion, déconnexion, rafraîchissement de jeton, etc.")
@RestController
@RequestMapping("/api/v1/auth")
@SecurityRequirements()
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    /**
     * Enregistre un nouvel utilisateur dans l'application.
     *
     * @param request Les informations de l'utilisateur à enregistrer
     * @return Une réponse d'authentification contenant les informations de l'utilisateur enregistré
     */
    @PostMapping("/register")
    @Operation(
            summary = "Enregistrer un nouvel utilisateur",
            description = "Crée un nouvel utilisateur dans l'application et retourne les informations d'authentification (jeton d'accès, jeton de rafraîchissement)",
            responses = {
                    @ApiResponse(
                            description = "Succès",
                            responseCode = "200",
                            content = {
                                    @Content(
                                            mediaType = "application/json",
                                            schema = @Schema(implementation = AuthenticationResponse.class)
                                    )
                            }
                    )
            }
    )
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthenticationResponse authenticationResponse = authenticationService.register(request);
        ResponseCookie jwtCookie = jwtService.generateJwtCookie(authenticationResponse.getAccessToken());
        ResponseCookie refreshTokenCookie = refreshTokenService.generateRefreshTokenCookie(authenticationResponse.getRefreshToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(authenticationResponse);
    }

    /**
     * Authentifie un utilisateur dans l'application.
     *
     * @param request Les informations d'authentification de l'utilisateur
     * @return Une réponse d'authentification contenant les informations de l'utilisateur authentifié
     */
    @PostMapping("/authenticate")
    @Operation(
            summary = "Authentifier un utilisateur",
            description = "Authentifie un utilisateur dans l'application et retourne les informations d'authentification (jeton d'accès, jeton de rafraîchissement)",
            responses = {
                    @ApiResponse(
                            description = "Succès",
                            responseCode = "200",
                            content = {
                                    @Content(
                                            mediaType = "application/json",
                                            schema = @Schema(implementation = AuthenticationResponse.class)
                                    )
                            }
                    ),
                    @ApiResponse(
                            description = "Non autorisé",
                            responseCode = "401",
                            content = {
                                    @Content(
                                            mediaType = "application/json",
                                            schema = @Schema(implementation = ErrorResponse.class)
                                    )
                            }
                    )
            }
    )
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        AuthenticationResponse authenticationResponse = authenticationService.authenticate(request);
        ResponseCookie jwtCookie = jwtService.generateJwtCookie(authenticationResponse.getAccessToken());
        ResponseCookie refreshTokenCookie = refreshTokenService.generateRefreshTokenCookie(authenticationResponse.getRefreshToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(authenticationResponse);
    }

    /**
     * refresh le jeton d'authentification de l'utilisateur.
     *
     * @param request Les informations de rafraîchissement du jeton
     * @return Une réponse contenant le nouveau jeton d'authentification
     */
    @PostMapping("/refresh-token")
    @Operation(
            summary = "Rafraîchir le jeton d'authentification",
            description = "Rafraîchit le jeton d'authentification de l'utilisateur à l'aide du jeton de rafraîchissement",
            responses = {
                    @ApiResponse(
                            description = "Succès",
                            responseCode = "200",
                            content = {
                                    @Content(
                                            mediaType = "application/json",
                                            schema = @Schema(implementation = RefreshTokenResponse.class)
                                    )
                            }
                    )
            }
    )
    public ResponseEntity<RefreshTokenResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(refreshTokenService.generateNewToken(request));
    }

    /**
     * faire un refresh le jeton d'authentification de l'utilisateur à partir des cookies.
     *
     * @param request La requête HTTP contenant les cookies
     * @return Une réponse contenant le nouveau jeton d'authentification
     */
    @PostMapping("/refresh-token-cookie")
    @Operation(
            summary = "Rafraîchir le jeton d'authentification à partir des cookies",
            description = "Rafraîchit le jeton d'authentification de l'utilisateur à l'aide du jeton de rafraîchissement stocké dans les cookies",
            responses = {
                    @ApiResponse(
                            description = "Succès",
                            responseCode = "200"
                    )
            }
    )
    public ResponseEntity<Void> refreshTokenCookie(HttpServletRequest request) {
        String refreshToken = refreshTokenService.getRefreshTokenFromCookies(request);
        RefreshTokenResponse refreshTokenResponse = refreshTokenService
                .generateNewToken(new RefreshTokenRequest(refreshToken));
        ResponseCookie NewJwtCookie = jwtService.generateJwtCookie(refreshTokenResponse.getAccessToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, NewJwtCookie.toString())
                .build();
    }

    /**
     * Déconnecte l'utilisateur en supprimant le jeton de rafraîchissement.
     *
     * @param request La requête HTTP contenant les cookies
     * @return Une réponse vide avec les cookies de jeton et de rafraîchissement supprimés
     */
    @PostMapping("/logout")
    @Operation(
            summary = "Déconnecter l'utilisateur",
            description = "Supprime le jeton de rafraîchissement de l'utilisateur et efface les cookies de jeton et de rafraîchissement",
            responses = {
                    @ApiResponse(
                            description = "Succès",
                            responseCode = "200"
                    )
            }
    )
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        String refreshToken = refreshTokenService.getRefreshTokenFromCookies(request);
        if (refreshToken != null) {
            refreshTokenService.deleteByToken(refreshToken);
        }
        ResponseCookie jwtCookie = jwtService.getCleanJwtCookie();
        ResponseCookie refreshTokenCookie = refreshTokenService.getCleanRefreshTokenCookie();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .build();
    }
}
