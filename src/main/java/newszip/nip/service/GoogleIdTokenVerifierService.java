package newszip.nip.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.List;
import newszip.nip.dto.GoogleIdTokenPayload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

// Google ID 토큰을 서버에서 검증
@Service
public class GoogleIdTokenVerifierService {

    private static final Logger log = LoggerFactory.getLogger(GoogleIdTokenVerifierService.class);
    private static final String GOOGLE_ISSUER = "https://accounts.google.com";
    private static final String GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs";

    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
    private final String clientId;

    public GoogleIdTokenVerifierService(
            @Value("${google.client-id:${GOOGLE_CLIENT_ID:}}") String clientId
    ) throws MalformedURLException {
        this.clientId = clientId;
        JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL(GOOGLE_JWKS));
        JWSAlgorithm expectedJwsAlg = JWSAlgorithm.RS256;
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJwsAlg, keySource);
        this.jwtProcessor = new DefaultJWTProcessor<>();
        this.jwtProcessor.setJWSKeySelector(keySelector);
    }

    public GoogleIdTokenPayload verify(String idToken) {
        if (idToken == null || idToken.isBlank()) {
            throw new IllegalArgumentException("ID 토큰이 비어 있습니다.");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("Google Client ID가 설정되지 않았습니다.");
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);

            // iss
            String issuer = claims.getIssuer();
            if (!GOOGLE_ISSUER.equals(issuer) && !"accounts.google.com".equals(issuer)) {
                throw new IllegalArgumentException("잘못된 issuer");
            }

            // aud
            List<String> audience = claims.getAudience();
            if (audience == null || !audience.contains(clientId)) {
                throw new IllegalArgumentException("audience 불일치");
            }

            // exp 자동 검증됨 (DefaultJWTProcessor)

            String email = claims.getStringClaim("email");
            Boolean emailVerified = claims.getBooleanClaim("email_verified");
            String name = claims.getStringClaim("name");
            String picture = claims.getStringClaim("picture");
            String sub = claims.getSubject();

            if (email == null || email.isBlank()) {
                throw new IllegalArgumentException("email 클레임이 없습니다.");
            }

            return GoogleIdTokenPayload.builder()
                    .sub(sub)
                    .email(email)
                    .emailVerified(Boolean.TRUE.equals(emailVerified))
                    .name(name)
                    .picture(picture)
                    .build();

        } catch (ParseException | JOSEException e) {
            log.warn("ID 토큰 파싱/검증 실패: {}", e.getMessage());
            throw new IllegalArgumentException("유효하지 않은 ID 토큰입니다.", e);
        } catch (Exception e) {
            log.warn("ID 토큰 검증 실패: {}", e.getMessage());
            throw new IllegalArgumentException("유효하지 않은 ID 토큰입니다.", e);
        }
    }
}

