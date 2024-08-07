package com.example.springsecurityjwt.repository;

import com.example.springsecurityjwt.entities.Role;
import com.example.springsecurityjwt.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long > {

    Optional<User> findByEmail(String email);

    User findByRole(Role role);
}
