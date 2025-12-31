package newszip.nip.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NaverUserInfo {

    private String resultcode;
    private String message;
    private NaverResponse response;

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NaverResponse {
        private String id;
        private String email;
        private String name;
        private String nickname;

        @JsonProperty("profile_image")
        private String profileImage;

        private String age;
        private String gender;
        private String birthday;
        private String birthyear;
        private String mobile;
    }

    public String getEmail() {
        return response != null ? response.getEmail() : null;
    }

    public Boolean isEmailVerified() {
        // 네이버는 이메일을 제공하면 검증된 것으로 간주
        return response != null && response.getEmail() != null && !response.getEmail().isBlank();
    }

    public String getName() {
        return response != null ? response.getName() : null;
    }

    public String getNickname() {
        return response != null ? response.getNickname() : null;
    }

    public String getId() {
        return response != null ? response.getId() : null;
    }
}

