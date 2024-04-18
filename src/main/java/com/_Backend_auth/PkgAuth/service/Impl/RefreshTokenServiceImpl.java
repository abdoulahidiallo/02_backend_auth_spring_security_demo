package com._Backend_auth.PkgAuth.service.Impl;

import com._Backend_auth.PkgAuth.dto.request.RefreshTokenRequest;
import com._Backend_auth.PkgAuth.dto.response.RefreshTokenResponse;
import com._Backend_auth.PkgAuth.entity.RefreshToken;
import com._Backend_auth.PkgAuth.entity.UserEntity;
import com._Backend_auth.PkgAuth.enums.TokenType;
import com._Backend_auth.PkgAuth.exceptions.TokenException;
import com._Backend_auth.PkgAuth.repository.RefreshTokenRepository;
import com._Backend_auth.PkgAuth.repository.UserRepository;
import com._Backend_auth.PkgAuth.service.JwtService;
import com._Backend_auth.PkgAuth.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.web.util.WebUtils;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Log4j2
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;
    @Value("${application.security.jwt.refresh-token.cookie-name}")
    private String refreshTokenName;

    /**
     * Crée un nouveau jeton de rafraîchissement pour l'utilisateur spécifié.
     *
     * @param userId L'identifiant de l'utilisateur
     * @return Le jeton de rafraîchissement créé
     */
    @Override
    public RefreshToken createRefreshToken(Integer userId) {
        UserEntity user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        RefreshToken refreshToken = RefreshToken.builder()
                .revoked(false)
                .userEntity(user)
                .token(Base64.getEncoder().encodeToString(UUID.randomUUID().toString().getBytes()))
                .expiryDate(Instant.now().plusMillis(refreshExpiration))
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Vérifie si le jeton de rafraîchissement est valide et non expiré.
     *
     * @param token Le jeton de rafraîchissement à vérifier
     * @return Le jeton de rafraîchissement s'il est valide
     * @throws TokenException Si le jeton est null ou expiré
     */
    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token == null) {
            log.error("Token is null");
            throw new TokenException(null, "Token is null");
        }
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            log.warn("Token expired at {}", token.getExpiryDate());
            refreshTokenRepository.delete(token);
            throw new TokenException(token.getToken(), "Refresh token was expired. Please make a new authentication request");
        }
        return token;
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Génère un nouveau jeton d'accès à partir d'un jeton de rafraîchissement valide.
     *
     * @param request Les informations du jeton de rafraîchissement
     * @return Une réponse contenant le nouveau jeton d'accès
     * @throws TokenException Si le jeton de rafraîchissement est invalide ou expiré
     */
    @Override
    public RefreshTokenResponse generateNewToken(RefreshTokenRequest request) {
        UserEntity user = refreshTokenRepository.findByToken(request.getRefreshToken())
                .map(this::verifyExpiration)
                .map(RefreshToken::getUserEntity)
                .orElseThrow(() -> new TokenException(request.getRefreshToken(), "Refresh token does not exist"));

        String token = jwtService.generateToken(user);
        return RefreshTokenResponse.builder()
                .accessToken(token)
                .refreshToken(request.getRefreshToken())
                .tokenType(TokenType.BEARER.name())
                .build();
    }

    @Override
    public ResponseCookie generateRefreshTokenCookie(String token) {
        return ResponseCookie.from(refreshTokenName, token)
                .path("/")
                .maxAge(refreshExpiration / 1000) // 15 days in seconds
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .build();
    }

    @Override
    public String getRefreshTokenFromCookies(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, refreshTokenName);
        if (cookie != null) {
            return cookie.getValue();
        } else {
            return "";
        }
    }

    @Override
    public void deleteByToken(String token) {
        Optional<RefreshToken> tokenOptional = refreshTokenRepository.findByToken(token);
        if (tokenOptional.isPresent()) {
            refreshTokenRepository.delete(tokenOptional.get());
        }
    }

    @Override
    public ResponseCookie getCleanRefreshTokenCookie() {
        return ResponseCookie.from(refreshTokenName, "")
                .path("/")
                .httpOnly(true)
                .maxAge(0)
                .build();
    }
}