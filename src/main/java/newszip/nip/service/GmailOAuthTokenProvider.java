package newszip.nip.service;

import java.time.Instant;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

// Gmail OAuth2 액세스 토큰을 리프레시 토큰으로 자동 갱신
@Component
public class GmailOAuthTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(GmailOAuthTokenProvider.class);
    private static final String TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
    private static final long REFRESH_SKEW_SECONDS = 60; // 만료 1분 전 갱신

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${gmail.oauth.client-id:${GOOGLE_CLIENT_ID:}}")
    private String clientId;

    @Value("${gmail.oauth.client-secret:${GOOGLE_CLIENT_SECRET:}}")
    private String clientSecret;

    @Value("${gmail.oauth.refresh-token:${GOOGLE_OAUTH_REFRESH_TOKEN}}")
    private String refreshToken;

    private String cachedAccessToken;
    private Instant expiresAt = Instant.EPOCH;

    public synchronized String getAccessToken() {
        validateConfig();
        Instant now = Instant.now();
        if (cachedAccessToken != null && now.isBefore(expiresAt.minusSeconds(REFRESH_SKEW_SECONDS))) {
            return cachedAccessToken;
        }
        return refreshAccessToken();
    }

    private String refreshAccessToken() {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> response = restTemplate.postForObject(
                    TOKEN_ENDPOINT,
                    new org.springframework.http.HttpEntity<>(body, createHeaders()),
                    Map.class
            );

            if (response == null || !response.containsKey("access_token")) {
                throw new IllegalStateException("Gmail 액세스 토큰 응답이 올바르지 않습니다.");
            }

            String accessToken = (String) response.get("access_token");
            Number expiresIn = (Number) response.getOrDefault("expires_in", 3600);

            this.cachedAccessToken = accessToken;
            this.expiresAt = Instant.now().plusSeconds(expiresIn.longValue());
            log.info("Gmail access token 갱신 완료 (유효기간: {}s)", expiresIn);
            return accessToken;
        } catch (HttpClientErrorException e) {
            log.error("Gmail access token 갱신 실패: {}", e.getResponseBodyAsString(), e);
            throw new IllegalStateException("Gmail access token 갱신에 실패했습니다.", e);
        } catch (Exception e) {
            log.error("Gmail access token 갱신 실패: {}", e.getMessage(), e);
            throw new IllegalStateException("Gmail access token 갱신에 실패했습니다.", e);
        }
    }

    private org.springframework.http.HttpHeaders createHeaders() {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }

    private void validateConfig() {
        if (isBlank(clientId) || isBlank(clientSecret) || isBlank(refreshToken)) {
            throw new IllegalStateException("Gmail OAuth2 설정이 누락되었습니다. gmail.oauth.client-id / client-secret / refresh-token 값을 확인하세요.");
        }
    }

    private boolean isBlank(String val) {
        return val == null || val.isBlank();
    }
}

