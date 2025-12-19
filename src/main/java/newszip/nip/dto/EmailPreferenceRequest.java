package newszip.nip.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

// 이메일 수신 동의 / 거부 요청
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailPreferenceRequest {

    @NotNull
    private Boolean emailOptIn; // true = 수신동의 / false = 수신 거부
}
