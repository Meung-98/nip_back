package newszip.nip.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

// 로그인 응답 DTO + 사용자 정보
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private String token;       // JWT 액세스 토큰
    private UserResponse user;  // 사용자 정보 요약
}
