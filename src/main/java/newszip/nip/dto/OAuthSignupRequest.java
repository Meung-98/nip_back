package newszip.nip.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

// OAuth2 회원가입 : 프로필 필수정보만 받아 2단계(카테고리 선택)로 이동
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuthSignupRequest {

    @Email
    @NotBlank
    private String userId;

    @NotBlank
    @Size(max = 20)
    private String username;

    // 선택입력(구글 프로필에 입력 정보 없을 시 null)
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
    private LocalDate birthDate;
}
