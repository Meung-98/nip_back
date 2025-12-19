package newszip.nip.model;

import jakarta.persistence.*;
import lombok.Getter;

@Getter
@Entity
@Table(
        name = "categories",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_categories_code",
                        columnNames = {"code"}
                )
        }
)
public class Category {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long categoryId;

    // 내부 식별 코드 (POLITICS, ECONOMY ...)
    @Column(nullable = false, length = 30)
    private String code;

    // 화면 표시용 이름 (정치, 경제 ...)
    @Column(nullable = false, length = 50)
    private String name;

    // 관리자 비활성화용
    @Column(nullable = false)
    private boolean enabled = true;

    // 노출 순서
    @Column(nullable = false)
    private int sortOrder;

}