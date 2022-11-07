package com.man.shop.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.man.shop.models.ERole;
import com.man.shop.models.Role;

public interface RoleRepository extends MongoRepository<Role, String> {
  Optional<Role> findByName(ERole name);
}
