package newszip.nip.service;

import newszip.nip.dto.KakaoUserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class KakaoTokenVerifierService {

    private static final Logger log = LoggerFactory.getLogger(KakaoTokenVerifierService.class);
    private static final String KAKAO_USER_INFO_URL = "https://kapi.kakao.com/v2/user/me";

    private final RestTemplate restTemplate;
    private final String clientId;

    public KakaoTokenVerifierService(
            @Value("${kakao.client-id:${KAKAO_CLIENT_ID:}}") String clientId
    ) {
        this.clientId = clientId;
        this.restTemplate = new RestTemplate();
    }

    public KakaoUserInfo verify(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("Access Token이 비어 있습니다.");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("카카오 Client ID가 설정되지 않았습니다.");
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);
            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<KakaoUserInfo> response = restTemplate.exchange(
                    KAKAO_USER_INFO_URL,
                    HttpMethod.GET,
                    entity,
                    KakaoUserInfo.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            } else {
                throw new IllegalArgumentException("카카오 사용자 정보를 가져올 수 없습니다.");
            }
        } catch (Exception e) {
            log.warn("카카오 토큰 검증 실패: {}", e.getMessage());
            throw new IllegalArgumentException("유효하지 않은 카카오 Access Token입니다.", e);
        }
    }
}
