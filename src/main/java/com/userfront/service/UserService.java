package com.userfront.service;


import com.userfront.domain.User;
import com.userfront.domain.security.UserRole;

import java.util.Set;

public interface UserService {
    User findByUsername(String name);

    User findByEmail(String email);

    boolean checkUserExists(String username, String email);

    boolean checkUsernameExists(String username);

    boolean checkEmailExists(String email);

    void save(User user);

    public User createUser(User user, Set<UserRole> userRoles);
}
