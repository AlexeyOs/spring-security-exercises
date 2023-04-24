package com.luxoft.spingsecurity.basicauth.security;

import com.luxoft.spingsecurity.basicauth.model.User;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Collections;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(encoder());
    }


    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/h2-console/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .csrf().disable()
                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/login", "/deny.html", "/logout").permitAll()
                .antMatchers("/user/whoami").permitAll()
                .antMatchers("/company/**", "/user/**").authenticated()
                .antMatchers("/info").hasAuthority("ROLE_ANON")
                .antMatchers("/**").denyAll()
                .and()
                .httpBasic()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .failureUrl("/deny.html")
                .defaultSuccessUrl("/company", true)
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .and()
                .anonymous()
                // ROLE_ANONYMOUS by default
                .authorities("ROLE_ANON")
                .principal(new UserDetailsAdapter(anonymous()))
                .and()
                .rememberMe()
                .alwaysRemember(true)
                .key("my-secret");
    }

    private static User anonymous() {
        val user = new User();
        user.setId(-1);
        user.setLogin("anonymous");
        user.setPassword("");
        user.setRoles(Collections.singletonList("ROLE_ANON"));
        return user;
    }
}