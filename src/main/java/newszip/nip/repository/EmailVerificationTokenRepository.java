package newszip.nip.repository;

import java.time.LocalDateTime;
import java.util.Optional;
import newszip.nip.model.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Long> {

    long countByEmailAndCreatedAtAfter(String email, LocalDateTime after);

    Optional<EmailVerificationToken> findTopByEmailAndCodeOrderByCreatedAtDesc(String email, String code);
}

