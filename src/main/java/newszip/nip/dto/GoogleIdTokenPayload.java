package newszip.nip.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

// 검증된 Google ID 토큰에서 추출한 주요 필드
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GoogleIdTokenPayload {
    private String sub;
    private String email;
    private boolean emailVerified;
    private String name;
    private String picture;
}

