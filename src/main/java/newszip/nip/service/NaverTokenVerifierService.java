package newszip.nip.service;

import newszip.nip.dto.NaverTokenResponse;
import newszip.nip.dto.NaverUserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

// 네이버 Access Token을 검증하고 사용자 정보를 가져오는 서비스
@Service
public class NaverTokenVerifierService {

    private static final Logger log = LoggerFactory.getLogger(NaverTokenVerifierService.class);
    private static final String NAVER_USER_INFO_URL = "https://openapi.naver.com/v1/nid/me";
    private static final String NAVER_TOKEN_URL = "https://nid.naver.com/oauth2.0/token";

    private final RestTemplate restTemplate;
    private final String clientId;
    private final String clientSecret;

    public NaverTokenVerifierService(
            @Value("${naver.client-id:${NAVER_CLIENT_ID:}}") String clientId,
            @Value("${naver.client-secret:${NAVER_CLIENT_SECRET:}}") String clientSecret
    ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.restTemplate = new RestTemplate();
    }

    // Authorization Code를 Access Token으로 교환
    public String exchangeAuthorizationCode(String code, String state, String redirectUri) {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("Authorization Code가 비어 있습니다.");
        }
        if (state == null || state.isBlank()) {
            throw new IllegalArgumentException("State가 비어 있습니다.");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("네이버 Client ID가 설정되지 않았습니다.");
        }
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalStateException("네이버 Client Secret이 설정되지 않았습니다.");
        }

        try {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "authorization_code");
            params.add("client_id", clientId);
            params.add("client_secret", clientSecret);
            params.add("code", code);
            params.add("state", state);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/x-www-form-urlencoded");
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);

            ResponseEntity<NaverTokenResponse> response = restTemplate.exchange(
                    NAVER_TOKEN_URL,
                    HttpMethod.POST,
                    entity,
                    NaverTokenResponse.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                NaverTokenResponse tokenResponse = response.getBody();

                if (tokenResponse.getError() != null) {
                    throw new IllegalArgumentException("네이버 토큰 교환 실패: " +
                            (tokenResponse.getErrorDescription() != null ? tokenResponse.getErrorDescription() : tokenResponse.getError()));
                }

                if (tokenResponse.getAccessToken() == null || tokenResponse.getAccessToken().isBlank()) {
                    throw new IllegalArgumentException("Access Token을 받아오지 못했습니다.");
                }

                return tokenResponse.getAccessToken();
            } else {
                throw new IllegalArgumentException("네이버 토큰 교환에 실패했습니다.");
            }
        } catch (Exception e) {
            log.warn("네이버 Authorization Code 교환 실패: {}", e.getMessage());
            if (e instanceof IllegalArgumentException) {
                throw e;
            }
            throw new IllegalArgumentException("네이버 토큰 교환 중 오류가 발생했습니다.", e);
        }
    }

    public NaverUserInfo verify(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("Access Token이 비어 있습니다.");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("네이버 Client ID가 설정되지 않았습니다.");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);
            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<NaverUserInfo> response = restTemplate.exchange(
                    NAVER_USER_INFO_URL,
                    HttpMethod.GET,
                    entity,
                    NaverUserInfo.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                NaverUserInfo userInfo = response.getBody();

                // 네이버 API 응답 검증
                if (!"00".equals(userInfo.getResultcode())) {
                    throw new IllegalArgumentException("네이버 API 오류: " + userInfo.getMessage());
                }

                return userInfo;
            } else {
                throw new IllegalArgumentException("네이버 사용자 정보를 가져올 수 없습니다.");
            }
        } catch (Exception e) {
            log.warn("네이버 토큰 검증 실패: {}", e.getMessage());
            throw new IllegalArgumentException("유효하지 않은 네이버 Access Token입니다.", e);
        }
    }
}


