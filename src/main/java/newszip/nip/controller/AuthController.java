package newszip.nip.controller;

import jakarta.validation.Valid;
import newszip.nip.dto.*;
import newszip.nip.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

// 회원가입 단계별 엔드포인트 제공하는 컨트롤러
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    // OAuth2(Google) 회원가입: 1단계 입력 없이 바로 2단계(카테고리 선택)로 진행
    @PostMapping("/signup/oauth/google")
    public ResponseEntity<UserResponse> oauthGoogleSignup(
            @Valid @RequestBody OAuthSignupRequest request
    ) {
        UserResponse response = userService.oauthSignupGoogle(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // STANDARD 로그인
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request
    ) {
        LoginResponse response = userService.login(request);
        return ResponseEntity.ok(response);
    }

    // OAuth 소셜 로그인 (Google 등)
    @PostMapping("/login/oauth")
    public ResponseEntity<LoginResponse> loginOAuth(
            @Valid @RequestBody OAuthLoginRequest request
    ) {
        LoginResponse response = userService.loginOAuth(request);
        return ResponseEntity.ok(response);
    }

    // 액세스 토큰 재발급 (리프레시 토큰 기반)
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        LoginResponse response = userService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    // 로그아웃: 리프레시 토큰 무효화
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal org.springframework.security.core.userdetails.User principal) {
        if (principal != null) {
            userService.logout(principal.getUsername());
        }
        return ResponseEntity.ok().build();
    }

    // 이메일 인증 코드 발송 (사용자 ID 기반)
    @PostMapping("/signup/{userId}/email/send-code")
    public ResponseEntity<UserResponse> sendEmailCode(
            @PathVariable Long userId
    ) {
        UserResponse response = userService.sendEmailVerificationCode(userId);
        return ResponseEntity.ok(response);
    }

    // 이메일 인증 코드 확인 (사용자 ID 기반)
    @PostMapping("/signup/{userId}/email/verify-code")
    public ResponseEntity<UserResponse> verifyEmailCode(
            @PathVariable Long userId,
            @Valid @RequestBody VerifyEmailCodeRequest request
    ) {
        UserResponse response = userService.verifyEmailCode(userId, request);
        return ResponseEntity.ok(response);
    }

    // 이메일 인증 코드 발송 (이메일 주소 기반 - 회원가입 전용)
    @PostMapping("/signup/email/send-code")
    public ResponseEntity<Void> sendEmailCodeByEmail(
            @RequestParam String email
    ) {
        userService.sendEmailVerificationCodeByEmail(email);
        return ResponseEntity.ok().build();
    }

    // 이메일 인증 코드 확인 (이메일 주소 기반 - 회원가입 전용)
    @PostMapping("/signup/email/verify-code")
    public ResponseEntity<Void> verifyEmailCodeByEmail(
            @RequestParam String email,
            @Valid @RequestBody VerifyEmailCodeRequest request
    ) {
        userService.verifyEmailCodeByEmail(email, request);
        return ResponseEntity.ok().build();
    }

    // 회원가입 1 단계 : 회원정보 저장 및 ROLE_USER 부여
    @PostMapping("/signup/step1")
    public ResponseEntity<UserResponse> signupStep1(
            @Valid @RequestBody SignupStep1Request request
    ) {
        UserResponse response = userService.signupStep1(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // 회원가입 2 단계 : 선호 카테고리 3 개 선택
    @PostMapping("/signup/{userId}/step2")
    public ResponseEntity<UserResponse> signupStep2(
            @PathVariable Long userId,
            @Valid @RequestBody SignupStep2Request request
    ) {
        UserResponse response = userService.signupStep2(userId, request);
        return ResponseEntity.ok(response);
    }

    // 수신 여부 설정
    @PostMapping("/signup/{userId}/email-preference")
    public ResponseEntity<UserResponse> updateEmailPreference(
            @PathVariable Long userId,
            @Valid @RequestBody EmailPreferenceRequest request
    ) {
        UserResponse response = userService.updateEmailPreference(userId, request);
        return ResponseEntity.ok(response);
    }

    // 가입 상태 조회
    @GetMapping("/signup/{userId}")
    public ResponseEntity<UserResponse> getUser(@PathVariable Long userId) {
        return ResponseEntity.ok(userService.getUser(userId));
    }
}
