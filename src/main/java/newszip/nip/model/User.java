package newszip.nip.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.Length;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(
        name = "nip_users",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_nip_users_user_id", columnNames = {"userId"})
        }
)
public class User {
    // 회원가입 1단계
    // 자동 증가 기본키
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 이메일형식 아이디 제한, OAuth 연결
    @Email(message = "이메일 형식이 올바르지 않습니다.")
    @NotBlank(message = "아이디(이메일)는 필수 입력값입니다.")
    @Column(nullable = false, unique = true, length = 100)
    private String userId;

    @NotBlank(message = "비밀번호는 필수 입력값입니다.")
    @Column(nullable = false)
    @Pattern(
            regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?])[A-Za-z\\d!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]{8,}$",
            message = "비밀번호는 8자 이상이며 영문, 숫자, 특수문자를 모두 포함해야 합니다."
    )
    private String password;

    @NotBlank
    @Column(nullable = false, length = 20)
    private String username;

    // 선택 입력
    private LocalDate birthDate;

    // 선택 입력
    @Column(nullable = true, length = 13)
    private String phone;

    // 저장시 자동 포맷팅
    @PrePersist
    @PreUpdate
    private void formatPhoneNumber() {
        if (this.phone == null || this.phone.isBlank()) {
            this.phone = null;
            return;
        }

        // 숫자만 남김
        String digits = this.phone.replaceAll("\\D", "");

        // 11자리 휴대폰 번호만 처리
        if (digits.length() == 11) {
            this.phone = digits.replaceFirst(
                    "(\\d{3})(\\d{4})(\\d{4})",
                    "$1-$2-$3"
            );
        }
    }

    // 회원가입 2단계
    // 뉴스 카테고리 : 3개 선택 (중복 방지 Set 사용)
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_categories",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "category_id"),
            uniqueConstraints = {
                    @UniqueConstraint(
                            name = "uk_user_category",
                            columnNames = {"user_id", "category_id"}
                    )
            }
    )
    @Builder.Default
    private Set<Category> categories = new HashSet<>();


    // 상태
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SignupStep signupStep;


    // 가입 / 인증 공급자
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private AuthProvider provider= AuthProvider.STANDARD;

    // 편의 메서드
    public boolean hasStandardPassword() {
        return this.password != null && !this.password.isBlank();
    }

    // 이메일 인증 여부 필드 추가
    @Builder.Default
    @Column(nullable = false)
    private boolean emailVerified = false;

    // 이메일 수신 동의 여부(기본값 동의)
    @Builder.Default
    @Column(nullable = false)
    private boolean emailOptIn = true;

    // 이메일 인증코드
    @Column(length = 6)
    private String emailVerificationCode;
    // 이메일 인증코드 만료 시각
    private LocalDateTime emailVerificationExpiresAt;

    // 이메일 발송 가능 여부 : 인증완료 + 수신 동의
    public boolean canReceiveEmail() {
        return emailVerified && emailOptIn;
    }


    // Role
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();


    // 사용자 상태
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;

    // 정지 종료 시점 (기간 정지용)
    private LocalDateTime suspendedUntil;

    // 관리자 제재 사유 (선택)
    @Column(length = 255)
    private String suspensionReason;

}
