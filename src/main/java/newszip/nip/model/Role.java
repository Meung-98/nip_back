package newszip.nip.model;

import jakarta.persistence.*;
import lombok.Getter;

@Getter
@Entity
@Table(
        name = "roles",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_roles_role_name",
                        columnNames = {"role_name"}
                )
        }
)
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long roleId;

    @Column(name = "role_name", nullable = false, length = 30)
    private String roleName;    // ROLE_USER, ROLE_ADMIN, ROLE_SUPER_ADMIN
}

