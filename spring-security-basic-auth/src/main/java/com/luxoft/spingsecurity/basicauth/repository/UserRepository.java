package com.luxoft.spingsecurity.basicauth.repository;

import com.luxoft.spingsecurity.basicauth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    @Query("select u from User u join fetch u.roles where u.login = :login ")
    Optional<User> fetchByLogin(@Param("login") String login);

}
