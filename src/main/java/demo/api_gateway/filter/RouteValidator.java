package demo.api_gateway.filter;

import java.util.List;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class RouteValidator {

    private static final List<String> PUBLIC_PATHS = List.of(
        "/v1/auth/login",
        "/v1/user/register",
        "/actuator/health"
    );

    public boolean isPublicPath(ServerHttpRequest request){
        return PUBLIC_PATHS.stream()
                    .anyMatch(publicPath -> request.getURI().getPath().startsWith(publicPath));
    }
}
