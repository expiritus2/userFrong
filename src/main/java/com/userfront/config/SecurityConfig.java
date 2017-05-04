package com.userfront.config;

import com.userfront.service.UserServiceImpl.UserSecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

    @Autowired
    private Environment env;

    @Autowired
    private UserSecurityService userSecurityService;

    private static final String SALT = "salt";

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(12, new SecureRandom(SALT.getBytes()));
    }

    private static final String[] PUBLIC_MATCHERS = {
            "/webjars/**",
            "/css/**",
            "/js/**",
            "/images/**",
            "/",
            "/about/**",
            "/contact/**",
            "/error/**/*",
            "/console/**",
            "/signup"
    };


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(PUBLIC_MATCHERS)
                .permitAll().anyRequest().authenticated();
        http
                .csrf().disable()
                .cors().disable()
                .formLogin()
                .successHandler(successHandler())
                .failureHandler(failureHandler())
                .loginPage("/index").permitAll()
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/index?logout").deleteCookies("remember-me").permitAll()
                .and()
                .rememberMe();
    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers(PUBLIC_MATCHERS)
//                .permitAll().anyRequest().authenticated();
//        http
//                .csrf().disable().cors().disable()
//                .formLogin().failureUrl("/index?error").defaultSuccessUrl()
//    }




    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userSecurityService).passwordEncoder(passwordEncoder());
    }

    private AuthenticationSuccessHandler successHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                httpServletResponse.getWriter().append("OK");
                httpServletResponse.setStatus(200);
            }
        };
    }

    private AuthenticationFailureHandler failureHandler() {
        return new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                httpServletResponse.getWriter().append("FAILURE");
                httpServletResponse.setStatus(401);
            }
        };
    }
}
