package nl.michelbijnen.ctf.gateway;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSource;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtTokenAuthenticationFilter implements WebFilter {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        try {
            final List<String> headerList = exchange.getRequest().getHeaders().get("Authorization");

            if (headerList == null) {
                return chain.filter(exchange);
            }

            final String header = headerList.get(0);

            final String token = header.replace("Bearer ", "");

            URL url = new URL("http:// " + System.getenv().getOrDefault("AUTHENTICATION_SERVICE_URL", "localhost") + ":" + System.getenv().getOrDefault("AUTHENTICATION_SERVICE_PORT", "8082") + "/checktoken");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");

            con.setRequestProperty("Authorization", token);

            int status = con.getResponseCode();

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

            if (exchange.getRequest().getHeaders().get("requestingUserId") != null) {
                this.logger.warn("User with userId '" + userId + "' tried to forge the requestingUserId header");
            }

            // Add the requestingUserId to the header
            exchange.getRequest().mutate().header("requestingUserId", userId);

            // Get role
            List<String> authorities = new ArrayList<>();
            authorities.add(role);

            // Authenticate the user
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userId, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
            SecurityContextHolder.getContext().setAuthentication(auth);

            this.logger.debug("Authenticated: " + SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
        } catch (IOException e) {
            this.logger.error(e.getMessage());
        }

        return chain.filter(exchange);
    }
}
