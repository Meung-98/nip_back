package newszip.nip.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

// Authorization 헤더의 Bearer 토큰을 검증하여 SecurityContext에 인증정보 세팅하는 필터
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String token = resolveToken(request);
        if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
            try {
                String userId = jwtTokenProvider.getSubject(token);
                UserDetails userDetails = userDetailsService.loadUserByUsername(userId);

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (org.springframework.security.core.userdetails.UsernameNotFoundException e) {
                // 사용자를 찾을 수 없는 경우 (예: 토큰은 유효하지만 사용자가 삭제됨)
                // 인증을 설정하지 않고 필터 체인을 계속 진행
                // 이는 OAuth 로그인 등 인증이 필요하지 않은 엔드포인트에서 유효하지 않은 토큰이 포함된 경우를 처리
            } catch (org.hibernate.LazyInitializationException e) {
                // LazyInitializationException 발생 시 (세션이 없는 경우)
                // 인증을 설정하지 않고 필터 체인을 계속 진행
                // 이는 permitAll() 엔드포인트에서 발생할 수 있는 문제를 처리
            } catch (Exception e) {
                // 기타 예외 발생 시에도 필터 체인을 계속 진행
                // 로그만 남기고 인증 실패로 처리하지 않음 (permitAll() 엔드포인트 보호)
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearer) && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }
}
