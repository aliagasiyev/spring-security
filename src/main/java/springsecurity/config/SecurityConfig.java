package springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    // Bu metodun əsas xüsusiyyəti Spring Security üçün bir təhlükəsizlik filtri zənciri (SecurityFilterChain)
    // yaratmasıdır.
    // Bu filtr zənciri, bütün HTTP sorğularına necə reaksiya veriləcəyini müəyyən edir.
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests((requests) -> requests.requestMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated());

       // Qeyd 24-cü setir bize deyirki gonderdiyimiz sorgular
        // statefull yoxsa stateless olmalidir onu secirik
       http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
       //http.formLogin(Customizer.withDefaults());
        http.headers(headers->headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        http.httpBasic(Customizer.withDefaults());
        http.csrf(AbstractHttpConfigurer::disable);
       return http.build();
    }



    // default olaraq in memeory istifade edib user1 ve admin yaratdiq
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1").
                password("{noop}ruhi123").
                roles("USER").
                build();

        UserDetails admin = User.withUsername("admin").
                password("{noop}password").
                roles("ADMIN").
                build();
        return new InMemoryUserDetailsManager(user1,admin);
    }

}
