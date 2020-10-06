package nl.michelbijnen.ctf.gateway;

import com.google.common.base.Charsets;
import com.google.common.io.ByteSource;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Filter;
import java.util.logging.LogRecord;
import java.util.stream.Collectors;

public class AuthenticationFilter extends OncePerRequestFilter {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        try {
            this.logger.debug("Started checking JWT token");

            final String headerName = "Authorization";
            final String tokenPrefix = "Bearer ";

            final String header = request.getHeader(headerName);

            if (header == null) {
                this.logger.debug("No Authorization headers found");
                chain.doFilter(request, response);
                return;
            }

            if (!header.startsWith(tokenPrefix)) {
                this.logger.debug("Authorization header does not start with 'Bearer '");
                chain.doFilter(request, response);
                return;
            }

            final String token = header.replace(tokenPrefix, "");

            URL url = new URL("http://localhost:8082/checktoken");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");

            con.setRequestProperty("Authorization", token);

            int status = con.getResponseCode();

            if (status > 299) {
                this.logger.warn("JWT token " + token + " invalid");
                // User is not authenticated
                chain.doFilter(request, response);
                return;
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

            this.logger.info("User with userId '" + userId + "' authorized access");
            if (request.getHeader("requestingUserId") != null) {
                this.logger.warn("User with userId '" + userId + "' tried to forge the requestingUserId header");
                chain.doFilter(request, response);
                return;
            }

            // Add the requestingUserId to the header
//            request.getHeader("requestingUserId") = "";

            // Get role
            List<String> authorities = new ArrayList<>();
            // TODO get this from auth request
            authorities.add("ROLE_USER");

            // Authenticate the user
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userId, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
            SecurityContextHolder.getContext().setAuthentication(auth);

            this.logger.debug("Authenticated: " + SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
        } catch (IOException e) {
            this.logger.error(e.getMessage());
        }

        chain.doFilter(request, response);
    }
}
