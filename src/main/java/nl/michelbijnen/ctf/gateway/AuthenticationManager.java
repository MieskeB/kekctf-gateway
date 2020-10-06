package nl.michelbijnen.ctf.gateway;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSource;
import nl.michelbijnen.ctf.gateway.exceptions.JWTInvalidException;
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

            URL url = new URL("http://localhost:8082/checktoken");
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

            List<String> authorities = new ArrayList<>();
            // TODO get this from auth request
            authorities.add("ROLE_USER");

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    userId,
                    null,
                    authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
            this.logger.info("User with userId '" + userId + "' authorized access");
            return Mono.just(auth);

        } catch (IOException e) {
            this.logger.warn(e.getMessage());
            authentication.setAuthenticated(false);
            return Mono.empty();
        }
    }
}
