package newszip.nip.service;

import newszip.nip.dto.*;

// 회원가입 단계별 처리 및 조회
public interface UserService {

    // OAuth2 구글 회원가입 : 1단계 화면 없이 2단계로 생성
    UserResponse oauthSignupGoogle(OAuthSignupRequest request);
    // 1 단계 : 회원 정보 저장 + ROLE 부여
    UserResponse signupStep1(SignupStep1Request request);
    // 2 단계 : 선호 카테고리 선택 및 가입 완료
    UserResponse signupStep2(Long userId, SignupStep2Request request);
    // 가입 상태 / 권한 / 선택 카테고리 조회
    UserResponse getUser(Long userId);
    // 이메일 수신 여부
    UserResponse updateEmailPreference(Long userId, EmailPreferenceRequest request);
    // STANDARD 로그인
    LoginResponse login(LoginRequest request);
}
