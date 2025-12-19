package newszip.nip.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

// 회원가입 2단계 : 선호 카테고리 선택 DTO (3개)
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignupStep2Request {

    @NotEmpty
    @Size(max = 3, message = "선호 카테고리는 최대 3개까지 선택 가능합니다.")
    private List<Long> categoryIds;
}
