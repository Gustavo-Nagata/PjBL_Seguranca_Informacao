package com.pucpr.service;

import com.pucpr.model.Usuario;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class JwtService {

    // Lê a chave diretamente da variável de ambiente do sistema operacional
    private final String SECRET_KEY = System.getenv("JWT_SECRET");

    /**
     * Método auxiliar para transformar a String da variável de ambiente
     * em uma SecretKey criptográfica usada pelo algoritmo HS256.
     */
    private SecretKey getSigningKey() {
        // Trava de segurança: Se a variável não estiver configurada, o sistema avisa na hora.
        if (SECRET_KEY == null || SECRET_KEY.trim().length() < 32) {
            throw new IllegalStateException("ERRO CRÍTICO: A variável de ambiente JWT_SECRET não está configurada ou tem menos de 32 caracteres!");
        }
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Gera o token assinado.
     */
    public String generateToken(Usuario user) {
        return Jwts.builder()
                .subject(user.getEmail())
                .claim("role", user.getRole())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900000)) // 15 min
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extrai o e-mail (subject) do token.
     */
    public String extractEmail(String token) {
        // 1 e 2. Descriptografa e pega o Subject (e-mail)
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload() // Em versões mais antigas do JJWT, isso se chamava .getBody()
                .getSubject();
    }

    /**
     * Valida se o token é autêntico e não expirou.
     */
    public boolean validateToken(String token) {
        try {
            // 1. Tenta fazer o parse do token.
            // O JJWT cuida de verificar a validade da data e a integridade da assinatura.
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            
            // 3. Se rodou a linha acima sem disparar erro, o token é válido.
            return true;

        } catch (JwtException e) {
            // 2 e 4. Cai aqui se o token for falso, tiver sido alterado ou estiver expirado.
            System.err.println("Falha na validação do Token: " + e.getMessage());
            return false;
        }
    }
}