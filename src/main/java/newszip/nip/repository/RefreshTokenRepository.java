package newszip.nip.repository;

import java.util.Optional;
import newszip.nip.model.RefreshToken;
import newszip.nip.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    void deleteByUser(User user);
}

