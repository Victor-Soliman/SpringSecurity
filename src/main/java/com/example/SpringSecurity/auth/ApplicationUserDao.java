package com.example.SpringSecurity.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Optional;


public interface ApplicationUserDao {

     Optional<ApplicationUser> selectApplicationUserByUserName(String username);

}
