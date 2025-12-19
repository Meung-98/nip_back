package newszip.nip.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

// Jwt 생성 및 검증
@Service
public class JwtTokenProvider {

    static final long EXPIRATION_TIME = 86400000;   // 하루
    static final String PREFIX = "Bearer ";
    private static final String DEFAULT_SECRET = "replace-this-with-your-own-64-byte-secret-key-string...........";

    @Value("${jwt.secret:" + DEFAULT_SECRET + "}")
    private String secret;

    @Value("${jwt.expiration-ms:" + EXPIRATION_TIME + "}")
    private long expirationMs;

    private SecretKey signingKey;

    @jakarta.annotation.PostConstruct
    void init() {
        // 최소 32바이트 이상으로 패딩
        if (secret.length() < 32) {
            secret = String.format("%-32s", secret).replace(' ', 'x');
        }
        signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // 로그인 토큰 생성 (subject=userId)
    public String generateToken(String userId) {
        Date now = new Date();
        return Jwts.builder()
                .subject(userId)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + expirationMs))
                .signWith(signingKey)
                .compact();
    }

    // Authorization 헤더에서 사용자 ID 추출
    public String getAuthUser(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (token != null && token.startsWith(PREFIX)) {
            try {
                return getSubject(token.substring(PREFIX.length()));
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    // 순수 토큰 문자열 기준 유효성 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // 토큰에서 subject 추출
    public String getSubject(String token) {
        Claims payload = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return payload.getSubject();
    }

    // 요청의 Authorization 헤더 기반 토큰 유효성 검사
    public boolean isValidToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(PREFIX)) {
            String token = header.substring(PREFIX.length());
            try {
                return validateToken(token);
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

    // 회원정보 재인증용 임시 토큰 발급
    public String issueReverifyToken(String userId, Duration ttl) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId)
                .audience().add("reverify").and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .claim("scope", "profile:edit")
                .signWith(signingKey)
                .compact();
    }

    // 재인증 토큰 검증: audience와 subject 확인
    public boolean verifyReverifyToken(String token, String expectedUserId) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        Object audience = claims.getAudience();
        boolean audienceOk = false;
        if (audience instanceof String str) {
            audienceOk = "reverify".equals(str);
        } else if (audience instanceof java.util.Collection<?> col) {
            audienceOk = col.contains("reverify");
        }
        if (!audienceOk) {
            return false;
        }
        return expectedUserId.equals(claims.getSubject());
    }

}
