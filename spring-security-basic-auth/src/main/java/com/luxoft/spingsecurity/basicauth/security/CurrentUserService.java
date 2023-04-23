package com.luxoft.spingsecurity.basicauth.security;

import com.luxoft.spingsecurity.basicauth.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class CurrentUserService {

    public User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsAdapter userDetails = (UserDetailsAdapter) auth.getPrincipal();
        return userDetails.getUser();
    }

}
