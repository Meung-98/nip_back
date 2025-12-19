package newszip.nip.dto;

import lombok.*;
import newszip.nip.model.AuthProvider;
import newszip.nip.model.UserStatus;

import java.util.List;
import java.util.Set;

// 회원 정보 조회 / 응답용 DTO : 상태, 권한, 선호 카테고리 포함
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {

    private Long id;
    private String userId;
    private String username;
    private boolean member;
    private UserStatus status;
    private AuthProvider provider;
    private boolean emailVerified;
    private boolean emailOptIn;                 // 이메일 수신 동의 여부
    private Set<String> roles;                  // ROLE 목록
    private List<CategorySummary> categories;   // 선호 카테고리

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CategorySummary {
        private Long id;            // CategoryId
        private String code;        // 내부 코드
        private String name;        // 노출 이름
        private boolean enabled;    // 사용 가능 여부
    }
}
