package newszip.nip.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

// STANDARD 로그인 요청 DTO
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @Email
    @NotBlank
    private String userId;

    @NotBlank
    private String password;
}
