package vn.giasutinhoc.demo.jwt.reponsitories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import vn.giasutinhoc.demo.jwt.common.ERole;
import vn.giasutinhoc.demo.jwt.entities.Role;

public interface RoleRepository extends JpaRepository<Role, Long> {
	Optional<Role> findByName(ERole name);
}
