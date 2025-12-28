package newszip.nip.service;

import newszip.nip.dto.*;

// 회원가입 단계별 처리 및 조회
public interface UserService {

    // OAuth2(Google) 회원가입 : 1단계 화면 없이 STEP2 상태로 생성
    UserResponse oauthSignupGoogle(OAuthSignupRequest request);
    // 1 단계 : 회원 정보 저장 + ROLE 부여
    UserResponse signupStep1(SignupStep1Request request);
    // 2 단계 : 선호 카테고리 선택 및 가입 완료
    UserResponse signupStep2(Long userId, SignupStep2Request request);
    // 가입 상태 / 권한 / 선택 카테고리 조회
    UserResponse getUser(Long userId);
    // 이메일 수신 여부
    UserResponse updateEmailPreference(Long userId, EmailPreferenceRequest request);
    // 이메일 인증 코드 발송 (사용자 ID 기반)
    UserResponse sendEmailVerificationCode(Long userId);
    // 이메일 인증 코드 확인 (사용자 ID 기반)
    UserResponse verifyEmailCode(Long userId, VerifyEmailCodeRequest request);
    // 이메일 인증 코드 발송 (이메일 주소 기반 - 회원가입 전용)
    void sendEmailVerificationCodeByEmail(String email);
    // 이메일 인증 코드 확인 (이메일 주소 기반 - 회원가입 전용)
    void verifyEmailCodeByEmail(String email, VerifyEmailCodeRequest request);
    // STANDARD 로그인
    LoginResponse login(LoginRequest request);
    // 리프레시 토큰으로 액세스 토큰 재발급
    LoginResponse refreshToken(RefreshTokenRequest request);
    // 로그아웃: 해당 사용자의 리프레시 토큰 무효화
    void logout(String userId);
    // 소셜(OAuth) 로그인: 프로필 수신 후 토큰 발급
    LoginResponse loginOAuth(OAuthLoginRequest request);
}
