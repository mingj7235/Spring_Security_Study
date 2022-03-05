package io.security.basic_security.theory;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity //web 보안을 활성하게 해주는 어노테이션
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http //인가 정책 설정
                .authorizeRequests()
                    .anyRequest().authenticated();
        //로그인 인증정책
        http //인증 정책 설정
                .formLogin();
//                .loginPage("/loginPage") // login 하도록 하는 page로 이동 하는 url
//                .defaultSuccessUrl("/")
//                .failureUrl("/login") // url 을 매핑해줌
//                .usernameParameter("userId") //default는 username이다
//                .passwordParameter("passwd") //default는 password이다.
//                .loginProcessingUrl("/login") //form tag의 action url이 여기에 매핑되는 것임. login 처리 api url 설정
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication : " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception : " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll();
        // 로그아웃 인증 정책
        http
                .logout()
//                .logoutUrl("/logout") // 원칙적으로 post 방식으로 logout 처리를 한다.
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate(); //session을 무력화 시키는것
//                    }
//                })
//                //logoutSuccessUrl과 비슷하지만, handler를 구현하면 더 많은 로직을 안에 넣을 수 있다.
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
                //쿠키의 이름을 적는다. 로그아웃시 이름을 적은 쿠키를 지워주는 것.
//                .deleteCookies("remember-me")
        .and()
                .rememberMe()
//                    .rememberMeParameter("remember") // default 값은 remember-me
//                    .tokenValiditySeconds(3600)
                    .userDetailsService(userDetailsService)
                ;

        // 동시 세션 제어
        http
                .sessionManagement()
                .sessionFixation().changeSessionId() //none으로 주면 세션 고정 공격에 대해 무방비가 된다.
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 세션 정책 설정 (If_Required 가 기본값임)
                .maximumSessions(1) //최대 허용 가능 세션 수
                .maxSessionsPreventsLogin(true) //default 값은 false. true : 동시 로그인을 차단한다. 즉, 후에 로그인하는 것을 막음 / false : 기존 세션을 만료시킴
        ;

    }

}