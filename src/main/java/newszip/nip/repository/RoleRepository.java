package newszip.nip.repository;

import newszip.nip.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// 권한 기반 조회
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByRoleName(String roleName);
}
