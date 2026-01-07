package newszip.nip.repository;

import newszip.nip.model.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// User 엔티티 CRUD 및 로그인 / 중복 체크용 조회
public interface UserRepository extends JpaRepository<User, Long> {

    boolean existsByUserId(String userId);

    @EntityGraph(attributePaths = {"roles", "categories"})
    Optional<User> findByUserId(String userId);


}
