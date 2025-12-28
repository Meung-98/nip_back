package newszip.nip.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import newszip.nip.model.AuthProvider;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

// 회원가입 1단계 : 회원정보 입력 DTO
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignupStep1Request {

    @Email
    @NotBlank
    private String userId;

    @NotBlank
    @Pattern(
            regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[!@#$%^&*])[A-Za-z\\d!@#$%^&*]{8,}$",
            message = "비밀번호는 영문, 숫자, 특수문자를 포함한 8자 이상이어야 합니다."
    )

    private String password;

    @NotBlank
    @Size(max = 20)
    private String username;

    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
    private LocalDate birthDate;


    @Pattern(
            regexp = "^$|^(\\d{10}|\\d{11})$",
            message = "전화번호는 숫자만 입력해야 합니다."
    )
    private String phone;

    private AuthProvider provider;

    // 이메일 수신 동의 여부 (기본값: true)
    private Boolean emailOptIn;
}
