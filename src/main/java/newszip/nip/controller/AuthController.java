package newszip.nip.controller;

import jakarta.validation.Valid;
import newszip.nip.dto.*;
import newszip.nip.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

// 회원가입 단계별 엔드포인트 제공하는 컨트롤러
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    // OAUTH2_GOOGLE 회원가입 : 계정인증 후 2단계(선호 카테고리)로 이동
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
