package newszip.nip.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

// 네이버 Authorization Code 처리 요청 DTO
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NaverAuthorizationCodeRequest {

    @NotBlank(message = "Authorization Code는 필수입니다.")
    private String code;

    @NotBlank(message = "State는 필수입니다.")
    private String state;

    @NotBlank(message = "Redirect URI는 필수입니다.")
    private String redirectUri;
}

