package springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Bu metodun əsas xüsusiyyəti Spring Security üçün bir təhlükəsizlik filtri zənciri (SecurityFilterChain)
    // yaratmasıdır.
    // Bu filtr zənciri, bütün HTTP sorğularına necə reaksiya veriləcəyini müəyyən edir.
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());

       // Qeyd 24-cü setir bize deyirki gonderdiyimiz sorgular
        // statefull yoxsa stateless olmalidir onu secirik
       http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
       //http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
       return http.build();
    }

}
