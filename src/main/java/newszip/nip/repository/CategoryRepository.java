package newszip.nip.repository;

import newszip.nip.model.Category;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

// 카테고리 조회 및 코드 중복 확인용
public interface CategoryRepository extends JpaRepository<Category, Long> {

    List<Category> findByCategoryIdIn(Collection<Long> ids);

    boolean existsByCode(String code);
}
