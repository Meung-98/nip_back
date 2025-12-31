package newszip.nip.service;

import newszip.nip.dto.*;
import newszip.nip.model.*;
import newszip.nip.repository.CategoryRepository;
import newszip.nip.repository.EmailVerificationTokenRepository;
import newszip.nip.repository.RefreshTokenRepository;
import newszip.nip.repository.RoleRepository;
import newszip.nip.repository.UserRepository;
import newszip.nip.security.jwt.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserServiceImpl implements UserService{
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final CategoryRepository categoryRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final EmailService emailService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final GoogleIdTokenVerifierService googleIdTokenVerifierService;
    private final KakaoTokenVerifierService kakaoTokenVerifierService;
    private final NaverTokenVerifierService naverTokenVerifierService;

    // 리프레시 토큰 유효기간 (일)
    @org.springframework.beans.factory.annotation.Value("${auth.refresh-token-days:14}")
    private long refreshTokenDays;

    // 이메일 인증 코드 유효시간(분)
    @org.springframework.beans.factory.annotation.Value("${auth.email-code-minutes:10}")
    private long emailCodeMinutes;

    // 이메일 인증 코드 재발송 쿨다운(초)
    @org.springframework.beans.factory.annotation.Value("${auth.email-code-resend-seconds:60}")
    private long emailCodeResendSeconds;

    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository, CategoryRepository categoryRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider, EmailService emailService, RefreshTokenRepository refreshTokenRepository, EmailVerificationTokenRepository emailVerificationTokenRepository, GoogleIdTokenVerifierService googleIdTokenVerifierService, KakaoTokenVerifierService kakaoTokenVerifierService, NaverTokenVerifierService naverTokenVerifierService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.categoryRepository = categoryRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.emailService = emailService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.emailVerificationTokenRepository = emailVerificationTokenRepository;
        this.googleIdTokenVerifierService = googleIdTokenVerifierService;
        this.kakaoTokenVerifierService = kakaoTokenVerifierService;
        this.naverTokenVerifierService = naverTokenVerifierService;
    }

    // OAuth2(Google) 회원가입: 1단계 화면 없이 바로 STEP2로 이동
    @Override
    public UserResponse oauthSignupGoogle(OAuthSignupRequest request) {
        if (userRepository.existsByUserId(request.getUserId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 가입된 이메일입니다.");
        }

        Role userRole = roleRepository.findByRoleName("ROLE_USER")
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "기본 권한(USER)이 설정되어 있지 않습니다."
                ));

        // OAuth 사용자는 임의 강력 비밀번호를 생성하여 저장 (패턴 충족)
        String randomPassword = UUID.randomUUID().toString() + "!Aa1";

        User user = User.builder()
                .userId(request.getUserId())
                .password(passwordEncoder.encode(randomPassword))
                .username(request.getUsername())
                .birthDate(request.getBirthDate())
                .provider(AuthProvider.OAUTH_GOOGLE)
                .signupStep(SignupStep.STEP2) // 바로 카테고리 선택 단계로 이동
                .status(UserStatus.ACTIVE)
                .emailOptIn(true) // 이메일 수신 동의 기본 true
                .build();

        user.getRoles().add(userRole);

        User saved = userRepository.save(user);
        return toResponse(saved);
    }

    // OAuth2(Kakao) 회원가입: 1단계 화면 없이 바로 STEP2로 이동
    @Override
    public UserResponse oauthSignupKakao(OAuthSignupRequest request) {
        if (userRepository.existsByUserId(request.getUserId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 가입된 이메일입니다.");
        }

        Role userRole = roleRepository.findByRoleName("ROLE_USER")
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "기본 권한(USER)이 설정되어 있지 않습니다."
                ));

        // OAuth 사용자는 임의 강력 비밀번호를 생성하여 저장 (패턴 충족)
        String randomPassword = UUID.randomUUID().toString() + "!Aa1";

        User user = User.builder()
                .userId(request.getUserId())
                .password(passwordEncoder.encode(randomPassword))
                .username(request.getUsername())
                .birthDate(request.getBirthDate())
                .provider(AuthProvider.OAUTH_KAKAO)
                .signupStep(SignupStep.STEP2) // 바로 카테고리 선택 단계로 이동
                .status(UserStatus.ACTIVE)
                .emailOptIn(true) // 이메일 수신 동의 기본 true
                .build();

        user.getRoles().add(userRole);

        User saved = userRepository.save(user);
        return toResponse(saved);
    }

    // OAuth2(Naver) 회원가입: 1단계 화면 없이 바로 STEP2로 이동
    @Override
    public UserResponse oauthSignupNaver(OAuthSignupRequest request) {
        if (userRepository.existsByUserId(request.getUserId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 가입된 이메일입니다.");
        }

        Role userRole = roleRepository.findByRoleName("ROLE_USER")
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "기본 권한(USER)이 설정되어 있지 않습니다."
                ));

        // OAuth 사용자는 임의 강력 비밀번호를 생성하여 저장 (패턴 충족)
        String randomPassword = UUID.randomUUID().toString() + "!Aa1";

        User user = User.builder()
                .userId(request.getUserId())
                .password(passwordEncoder.encode(randomPassword))
                .username(request.getUsername())
                .birthDate(request.getBirthDate())
                .provider(AuthProvider.OAUTH_NAVER)
                .signupStep(SignupStep.STEP2) // 바로 카테고리 선택 단계로 이동
                .status(UserStatus.ACTIVE)
                .emailOptIn(true) // 이메일 수신 동의 기본 true
                .build();

        user.getRoles().add(userRole);

        User saved = userRepository.save(user);
        return toResponse(saved);
    }

    // 1 단계 : 중복 이메일 확인 → 권한 조회 → 사용자 저장
    @Override
    public UserResponse signupStep1(SignupStep1Request request) {
        if (userRepository.existsByUserId(request.getUserId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 가입된 이메일입니다.");
        }

        Role userRole = roleRepository.findByRoleName("ROLE_USER")
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "기본 권한(USER)이 설정되어 있지 않습니다."
                ));

        AuthProvider provider = request.getProvider() != null
                ? request.getProvider()
                : AuthProvider.STANDARD;

        // phone이 null이거나 빈 문자열이면 null로 설정 (선택 입력)
        String phone = (request.getPhone() == null || request.getPhone().trim().isEmpty())
                ? null
                : request.getPhone();

        // 이메일 수신 동의 여부 (기본값: true)
        boolean emailOptIn = request.getEmailOptIn() != null
                ? request.getEmailOptIn()
                : true;

        User user = User.builder()
                .userId(request.getUserId())
                .password(passwordEncoder.encode(request.getPassword()))
                .username(request.getUsername())
                .birthDate(request.getBirthDate())
                .phone(phone)
                .provider(provider)
                .signupStep(SignupStep.STEP1)
                .status(UserStatus.ACTIVE)
                .emailOptIn(emailOptIn)
                .build();

        user.getRoles().add(userRole);

        User saved = userRepository.save(user);
        return toResponse(saved);
    }

    // 2 단계 : 카테고리 3 개 검증 후 COMPLETE 전환
    @Override
    public UserResponse signupStep2(Long userId, SignupStep2Request request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."));

        if (user.getSignupStep() == SignupStep.COMPLETE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "이미 가입을 완료한 사용자입니다.");
        }

        if (request.getCategoryIds() == null || request.getCategoryIds().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "카테고리를 한 개 이상 선택해야 합니다.");
        }

        if (request.getCategoryIds().size() > 3) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "선호 카테고리는 최대 3 개까지 선택 가능합니다.");
        }

        Set<Long> distinctIds = new HashSet<>(request.getCategoryIds());
        List<Category> categories = categoryRepository.findByCategoryIdIn(distinctIds);

        if (categories.size() != distinctIds.size()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "존재하지 않는 카테고리가 포함되어 있습니다.");
        }

        categories.stream()
                .filter(category -> !category.isEnabled())
                .findFirst()
                .ifPresent(category -> {
                    throw new ResponseStatusException(HttpStatus.NOT_FOUND, "비활성화된 카테고리는 선택할 수 없습니다.");
                });

        user.getCategories().clear();
        user.getCategories().addAll(categories);
        user.setSignupStep(SignupStep.COMPLETE);

        User saved = userRepository.save(user);
        return toResponse(saved);
    }

    // 사용자 조회 (READ ONLY)
    @Override
    @Transactional(readOnly = true)
    public UserResponse getUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."));
        return toResponse(user);
    }

    // 엔티티 → 응답 DTO 변환
    private UserResponse toResponse(User user) {
        boolean isMember = user.getSignupStep() == SignupStep.COMPLETE;

        Set<String> roleNames = isMember
                ? user.getRoles().stream()
                .map(Role::getRoleName)
                .collect(Collectors.toCollection(TreeSet::new))
                : Collections.emptySet();

        List<UserResponse.CategorySummary> categorySummaries = isMember
                ? user.getCategories().stream()
                .sorted(Comparator.comparing(Category::getSortOrder))
                .map(category -> UserResponse.CategorySummary.builder()
                        .id(category.getCategoryId())
                        .code(category.getCode())
                        .name(category.getName())
                        .enabled(category.isEnabled())
                        .build())
                .toList()
                : Collections.emptyList();

        return UserResponse.builder()
                .id(user.getId())
                .userId(user.getUserId())
                .username(user.getUsername())
                .member(isMember)
                .status(user.getStatus())
                .provider(user.getProvider())
                .emailVerified(user.isEmailVerified())
                .emailOptIn(user.isEmailOptIn())
                .roles(roleNames)
                .categories(categorySummaries)
                .build();
    }

    @Override
    public UserResponse updateEmailPreference(Long userId, EmailPreferenceRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."));

        if (!user.isEmailVerified()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "이메일 인증 후에 수신 여부를 설정할 수 있습니다.");
        }

        user.setEmailOptIn(Boolean.TRUE.equals(request.getEmailOptIn()));
        User saved = userRepository.save(user);
        return toResponse(saved);
    }

    // 이메일 인증 코드 발송
    @Override
    public UserResponse sendEmailVerificationCode(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."));

        if (user.isEmailVerified()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "이미 이메일 인증을 완료한 사용자입니다.");
        }

        // 쿨다운 체크
        LocalDateTime threshold = LocalDateTime.now().minusSeconds(emailCodeResendSeconds);
        long recentCount = emailVerificationTokenRepository.countByEmailAndCreatedAtAfter(user.getUserId(), threshold);
        if (recentCount > 0) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "잠시 후 다시 시도해 주세요. (재발송 쿨다운)");
        }

        String code = generateVerificationCode(6);
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(emailCodeMinutes);

        EmailVerificationToken token = EmailVerificationToken.builder()
                .email(user.getUserId())
                .code(code)
                .expiresAt(expiresAt)
                .createdAt(LocalDateTime.now())
                .consumed(false)
                .build();
        emailVerificationTokenRepository.save(token);

        emailService.sendVerificationCode(user.getUserId(), code, emailCodeMinutes);

        return toResponse(user);
    }

    // 이메일 인증 코드 발송 (이메일 주소 기반 - 회원가입 전용)
    @Override
    public void sendEmailVerificationCodeByEmail(String email) {
        // 이미 가입된 이메일인지 확인
        if (userRepository.existsByUserId(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 가입된 이메일입니다.");
        }

        // 쿨다운 체크
        LocalDateTime threshold = LocalDateTime.now().minusSeconds(emailCodeResendSeconds);
        long recentCount = emailVerificationTokenRepository.countByEmailAndCreatedAtAfter(email, threshold);
        if (recentCount > 0) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "잠시 후 다시 시도해 주세요. (재발송 쿨다운)");
        }

        String code = generateVerificationCode(6);
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(emailCodeMinutes);

        EmailVerificationToken token = EmailVerificationToken.builder()
                .email(email)
                .code(code)
                .expiresAt(expiresAt)
                .createdAt(LocalDateTime.now())
                .consumed(false)
                .build();
        emailVerificationTokenRepository.save(token);

        emailService.sendVerificationCode(email, code, emailCodeMinutes);
    }

    // 이메일 인증 코드 확인 (이메일 주소 기반 - 회원가입 전용)
    @Override
    public void verifyEmailCodeByEmail(String email, VerifyEmailCodeRequest request) {
        EmailVerificationToken token = emailVerificationTokenRepository
                .findTopByEmailAndCodeOrderByCreatedAtDesc(email, request.getCode().trim())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "인증 코드가 올바르지 않습니다."));

        if (token.isConsumed()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "이미 사용된 인증 코드입니다.");
        }

        if (LocalDateTime.now().isAfter(token.getExpiresAt())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "인증 코드가 만료되었습니다. 코드를 다시 요청해 주세요.");
        }

        // 토큰 소비 처리
        token.setConsumed(true);
        emailVerificationTokenRepository.save(token);
    }

    // 이메일 인증 코드 검증
    @Override
    public UserResponse verifyEmailCode(Long userId, VerifyEmailCodeRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."));

        if (user.isEmailVerified()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "이미 이메일 인증을 완료한 사용자입니다.");
        }

        EmailVerificationToken token = emailVerificationTokenRepository
                .findTopByEmailAndCodeOrderByCreatedAtDesc(user.getUserId(), request.getCode())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "인증 코드가 올바르지 않습니다."));

        if (token.isConsumed()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "이미 사용된 인증 코드입니다.");
        }

        if (token.isExpired(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "인증 코드가 만료되었습니다. 코드를 다시 요청해 주세요.");
        }

        user.setEmailVerified(true);
        token.setConsumed(true);

        User saved = userRepository.save(user);
        emailVerificationTokenRepository.save(token);
        return toResponse(saved);
    }

    // STANDARD 로그인 : 자격 검증 후 JWT 발급
    @Override
    public LoginResponse login(LoginRequest request) {
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(request.getUserId(), request.getPassword());

        try {
            authenticationManager.authenticate(authToken);
        } catch (BadCredentialsException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "아이디 또는 비밀번호가 올바르지 않습니다.");
        }

        User user = userRepository.findByUserId(request.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "비활성화된 사용자입니다.");
        }

        String token = jwtTokenProvider.generateToken(user.getUserId());
        RefreshToken refreshToken = issueRefreshToken(user);

        return LoginResponse.builder()
                .token(token)
                .refreshToken(refreshToken.getToken())
                .user(toResponse(user))
                .build();
    }

    // 리프레시 토큰 재발급 및 액세스 토큰 갱신
    @Override
    public LoginResponse refreshToken(RefreshTokenRequest request) {
        RefreshToken stored = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 리프레시 토큰입니다."));

        if (stored.isRevoked()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "이미 사용된 리프레시 토큰입니다.");
        }

        if (LocalDateTime.now().isAfter(stored.getExpiresAt())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "리프레시 토큰이 만료되었습니다.");
        }

        User user = stored.getUser();
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "비활성화된 사용자입니다.");
        }

        // 기존 토큰 폐기 후 새 토큰 발급 (회전)
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);
        RefreshToken newRefresh = issueRefreshToken(user);

        String newAccessToken = jwtTokenProvider.generateToken(user.getUserId());
        return LoginResponse.builder()
                .token(newAccessToken)
                .refreshToken(newRefresh.getToken())
                .user(toResponse(user))
                .build();
    }

    // 로그아웃: 해당 사용자의 리프레시 토큰 모두 무효화
    @Override
    public void logout(String userId) {
        userRepository.findByUserId(userId).ifPresent(refreshTokenRepository::deleteByUser);
    }

    private RefreshToken issueRefreshToken(User user) {
        // 기존 토큰 정리: 한 사용자당 하나만 유지
        refreshTokenRepository.deleteByUser(user);

        String tokenValue = generateRandomString(64);
        RefreshToken refreshToken = RefreshToken.builder()
                .token(tokenValue)
                .user(user)
                .expiresAt(LocalDateTime.now().plus(refreshTokenDays, ChronoUnit.DAYS))
                .revoked(false)
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    private String generateRandomString(int length) {
        final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return sb.toString();
    }

    // 소셜(OAuth) 로그인: provider 매칭, 없으면 자동 생성(STEP2 상태)
    @Override
    public LoginResponse loginOAuth(OAuthLoginRequest request) {
        AuthProvider provider = request.getProvider();
        if (provider == null || provider == AuthProvider.STANDARD) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "유효한 OAuth 공급자가 필요합니다.");
        }

        // Google ID 토큰 검증 (Google일 때 필수)
        if (provider == AuthProvider.OAUTH_GOOGLE) {
            if (request.getIdToken() == null || request.getIdToken().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Google ID 토큰이 필요합니다.");
            }
            try {
                var payload = googleIdTokenVerifierService.verify(request.getIdToken());
                // ID 토큰의 이메일/이름/검증 여부를 신뢰값으로 사용
                request = OAuthLoginRequest.builder()
                        .userId(payload.getEmail())
                        .username(payload.getName() == null ? payload.getEmail() : payload.getName())
                        .provider(provider)
                        .emailVerified(payload.isEmailVerified())
                        .emailOptIn(request.getEmailOptIn())
                        .build();
            } catch (IllegalArgumentException ex) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 Google ID 토큰입니다.", ex);
            }
        }

        // 카카오 Access Token 검증 (카카오일 때 필수)
        if (provider == AuthProvider.OAUTH_KAKAO) {
            if (request.getIdToken() == null || request.getIdToken().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "카카오 Access Token이 필요합니다.");
            }
            try {
                var kakaoUserInfo = kakaoTokenVerifierService.verify(request.getIdToken());
                String email = kakaoUserInfo.getEmail();
                if (email == null || email.isBlank()) {
                    // 카카오 이메일이 없는 경우, 카카오 ID를 기반으로 이메일 생성
                    email = "kakao_" + kakaoUserInfo.getId() + "@kakao.temp";
                }
                String nickname = kakaoUserInfo.getNickname();
                request = OAuthLoginRequest.builder()
                        .userId(email)
                        .username(nickname != null && !nickname.isBlank() ? nickname : email)
                        .provider(provider)
                        .emailVerified(kakaoUserInfo.isEmailVerified())
                        .emailOptIn(request.getEmailOptIn())
                        .build();
            } catch (IllegalArgumentException ex) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 카카오 Access Token입니다.", ex);
            }
        }

        // 네이버 Access Token 검증 (네이버일 때 필수)
        // 단, loginNaverWithCode에서 이미 검증한 경우 userId가 이미 설정되어 있으므로 건너뜀
        if (provider == AuthProvider.OAUTH_NAVER) {
            // userId가 이미 설정되어 있으면 loginNaverWithCode에서 이미 검증된 것으로 간주
            if (request.getUserId() != null && !request.getUserId().isBlank()) {
                // 이미 검증된 사용자 정보 사용
            } else if (request.getIdToken() == null || request.getIdToken().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "네이버 Access Token이 필요합니다.");
            } else {
                try {
                    var naverUserInfo = naverTokenVerifierService.verify(request.getIdToken());
                    String email = naverUserInfo.getEmail();
                    if (email == null || email.isBlank()) {
                        // 네이버 이메일이 없는 경우, 네이버 ID를 기반으로 이메일 생성
                        email = "naver_" + naverUserInfo.getId() + "@naver.temp";
                    }
                    String name = naverUserInfo.getName();
                    String nickname = naverUserInfo.getNickname();
                    String username = nickname != null && !nickname.isBlank()
                            ? nickname
                            : (name != null && !name.isBlank() ? name : email);
                    request = OAuthLoginRequest.builder()
                            .userId(email)
                            .username(username)
                            .provider(provider)
                            .emailVerified(naverUserInfo.isEmailVerified())
                            .emailOptIn(request.getEmailOptIn())
                            .build();
                } catch (IllegalArgumentException ex) {
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 네이버 Access Token입니다.", ex);
                }
            }
        }

        Optional<User> existing = userRepository.findByUserId(request.getUserId());
        User user;
        if (existing.isPresent()) {
            user = existing.get();
            if (user.getProvider() != provider) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "다른 가입 방식으로 이미 등록된 이메일입니다.");
            }
            if (user.getStatus() != UserStatus.ACTIVE) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "비활성화된 사용자입니다.");
            }
        } else {
            Role userRole = roleRepository.findByRoleName("ROLE_USER")
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            "기본 권한(USER)이 설정되어 있지 않습니다."
                    ));

            String randomPassword = generateRandomString(24) + "!Aa1";
            boolean emailVerified = request.getEmailVerified() != null ? request.getEmailVerified() : true;
            boolean emailOptIn = request.getEmailOptIn() == null ? true : request.getEmailOptIn();
            String username = request.getUsername() != null && !request.getUsername().isBlank()
                    ? request.getUsername()
                    : request.getUserId();

            user = User.builder()
                    .userId(request.getUserId())
                    .password(passwordEncoder.encode(randomPassword))
                    .username(username)
                    .provider(provider)
                    .signupStep(SignupStep.STEP2) // 카테고리 선택 대기 상태
                    .status(UserStatus.ACTIVE)
                    .emailVerified(emailVerified)
                    .emailOptIn(emailOptIn)
                    .build();
            user.getRoles().add(userRole);
            user = userRepository.save(user);
        }

        String accessToken = jwtTokenProvider.generateToken(user.getUserId());
        RefreshToken refreshToken = issueRefreshToken(user);

        return LoginResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken.getToken())
                .user(toResponse(user))
                .build();
    }

    private String generateVerificationCode(int length) {
        final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return sb.toString();
    }

    // 네이버 Authorization Code로 로그인
    @Override
    public LoginResponse loginNaverWithCode(String code, String state, String redirectUri) {
        // Authorization Code를 Access Token으로 교환
        String accessToken;
        try {
            accessToken = naverTokenVerifierService.exchangeAuthorizationCode(code, state, redirectUri);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, ex.getMessage(), ex);
        }

        // Access Token으로 사용자 정보 조회
        try {
            var naverUserInfo = naverTokenVerifierService.verify(accessToken);
            String email = naverUserInfo.getEmail();
            if (email == null || email.isBlank()) {
                // 네이버 이메일이 없는 경우, 네이버 ID를 기반으로 이메일 생성
                email = "naver_" + naverUserInfo.getId() + "@naver.temp";
            }
            String name = naverUserInfo.getName();
            String nickname = naverUserInfo.getNickname();
            String username = nickname != null && !nickname.isBlank()
                    ? nickname
                    : (name != null && !name.isBlank() ? name : email);

            OAuthLoginRequest oauthRequest = OAuthLoginRequest.builder()
                    .userId(email)
                    .username(username)
                    .provider(AuthProvider.OAUTH_NAVER)
                    .emailVerified(naverUserInfo.isEmailVerified())
                    .emailOptIn(true)
                    .build();

            return loginOAuth(oauthRequest);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 네이버 Access Token입니다.", ex);
        }
    }
}

