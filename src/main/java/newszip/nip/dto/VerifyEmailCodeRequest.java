package newszip.nip.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

// 이메일 인증 코드 검증 요청
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyEmailCodeRequest {

    @NotBlank
    @Pattern(regexp = "^[A-Z0-9]{6}$", message = "인증 코드는 영문 대문자/숫자 6자리여야 합니다.")
    private String code;
}

