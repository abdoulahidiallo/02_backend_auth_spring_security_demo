package com._Backend_auth.PkgAuth.config.filters;

import com._Backend_auth.PkgAuth.service.JwtService;
import io.micrometer.common.util.StringUtils;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * Méthode exécutée pour chaque requête entrante.
     * Elle vérifie la présence et la validité du jeton JWT, et met à jour le contexte de sécurité Spring Security en conséquence.
     *
     * @param request     la requête HTTP entrante
     * @param response    la réponse HTTP
     * @param filterChain la chaîne de filtres à exécuter
     * @throws ServletException en cas d'erreur lors du traitement de la requête
     * @throws IOException      en cas d'erreur d'entrée/sortie
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // Essaie de récupérer le jeton JWT dans les cookies ou dans l'en-tête "Authorization"
        String jwt = jwtService.getJwtFromCookies(request);
        final String authHeader = request.getHeader("Authorization");

        // Si le jeton JWT n'est pas présent et que la requête ne concerne pas l'authentification, on passe au prochain filtre
        if ((jwt == null && (authHeader == null || !authHeader.startsWith("Bearer "))) || request.getRequestURI().contains("/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Si le jeton JWT n'est pas dans les cookies mais dans l'en-tête "Authorization"
        if (jwt == null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7); // après "Bearer "
        }

        // Extrait le nom d'utilisateur (email) à partir du jeton JWT
        final String userEmail = jwtService.extractUserName(jwt);

        // Si le nom d'utilisateur est valide et qu'aucun utilisateur n'est encore authentifié
        if (StringUtils.isNotEmpty(userEmail)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Charge les détails de l'utilisateur à partir du service UserDetailsService
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // Vérifie la validité du jeton JWT
            if (jwtService.isTokenValid(jwt, userDetails)) {
                // Met à jour le contexte de sécurité Spring Security avec les informations d'authentification
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                context.setAuthentication(authToken);
                SecurityContextHolder.setContext(context);
            }
        }
        // Passe au prochain filtre de la chaîne
        filterChain.doFilter(request, response);
    }
}