package newszip.nip.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import newszip.nip.model.AuthProvider;

// 소셜 로그인 요청 DTO (토큰 검증은 외부에서 수행하고, 여기서는 신뢰된 프로필만 수신)
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuthLoginRequest {

    @Email
    @NotBlank
    private String userId;          // 이메일 (unique id)

    private String username;        // 표시 이름 (미제공 시 userId 사용)

    // Google 등에서 발급한 ID 토큰 (서버 검증용). Google일 때 필수로 사용하는 것을 권장.
    private String idToken;

    @NotNull
    private AuthProvider provider;  // OAUTH_GOOGLE 등

    @Builder.Default
    private boolean emailVerified = true; // 외부에서 이메일 검증을 보장했다고 가정

    private Boolean emailOptIn;     // 선택값, null이면 기본 true
}

