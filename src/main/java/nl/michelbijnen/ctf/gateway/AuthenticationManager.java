package nl.michelbijnen.ctf.gateway;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSource;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class AuthenticationManager implements ReactiveAuthenticationManager {
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        try {
            this.logger.debug("Checking JWT token");

            String token = authentication.getCredentials().toString();

            String host = System.getenv("AUTHENTICATION_SERVICE_URL");
            if (host == null) {
                host = "localhost";
            }
            String port = System.getenv("AUTHENTICATION_SERVICE_PORT");
            if (port == null) {
                port = "8082";
            }
            URL url = new URL("http:// " + host + ":" + port + "/checktoken");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");

            con.setRequestProperty("Authorization", token);

            int status = con.getResponseCode();

            if (status > 299) {
                this.logger.warn("JWT token " + token + " invalid");
                return Mono.empty();
            }

            InputStream inputStream = con.getInputStream();
            ByteSource byteSource = new ByteSource() {
                @Override
                public InputStream openStream() throws IOException {
                    return inputStream;
                }
            };
            JSONObject body = new JSONObject(byteSource.asCharSource(Charsets.UTF_8).read());
            String userId = body.getString("userId");
            String role = body.getString("role");

            if (role == null) {
                role = "ROLE_USER";
            }

            List<String> authorities = new ArrayList<>();
            authorities.add(role);

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    userId,
                    null,
                    authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
            this.logger.info("User with userId '" + userId + "' and role '" + role + "' authorized access");
            return Mono.just(auth);

        } catch (IOException e) {
            e.printStackTrace();
            this.logger.warn(e.getMessage());
            authentication.setAuthenticated(false);
            return Mono.empty();
        }
    }
}
