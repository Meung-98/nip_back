package newszip.nip.service;

import newszip.nip.dto.*;
import newszip.nip.model.*;
import newszip.nip.repository.CategoryRepository;
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

    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository, CategoryRepository categoryRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.categoryRepository = categoryRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // OAuth2 GOOGLE 회원가입 : 1단계 화면 없이 바로 2단계로 이동
    @Override
    public UserResponse oauthSignupGoogle(OAuthSignupRequest request) {
        if (userRepository.existsByUserId(request.getUserId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 가입된 이메일입니다.");
        }
        Role userRole = roleRepository.findByRoleName("ROLE_USER")
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.INTERNAL_SERVER_ERROR, "기본 권한(USER)이 설정되어 있지 않습니다."
                ));

        // OAuth2 사용자는 임의 강력 비밀번호를 생성하여 저장(패턴 충족)
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

        User user = User.builder()
                .userId(request.getUserId())
                .password(passwordEncoder.encode(request.getPassword()))
                .username(request.getUsername())
                .birthDate(request.getBirthDate())
                .phone(request.getPhone())
                .provider(provider)
                .signupStep(SignupStep.STEP1)
                .status(UserStatus.ACTIVE)
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

        return LoginResponse.builder()
                .token(token)
                .user(toResponse(user))
                .build();
    }
}

