package demo.api_gateway.Unit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import demo.api_gateway.filter.AuthenticationFilter;
import demo.api_gateway.util.JwtUtil;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

@ExtendWith(MockitoExtension.class)
public class AuthenticationFilterTest {
    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private GatewayFilterChain chain;

    private AuthenticationFilter authenticationFilter;
    private GatewayFilter gatewayFilter;

    @BeforeEach
    void setUp(){
        authenticationFilter = new AuthenticationFilter(jwtUtil);
        gatewayFilter = authenticationFilter.apply(new AuthenticationFilter.Config());

        when(chain.filter(any(ServerWebExchange.class)))
            .thenReturn(Mono.empty());
    }

    @Test
    void filter_PublicPath_Success_WithoutToken(){
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .post("/v1/user/register")
            .contentType(MediaType.APPLICATION_JSON)
            .body("""
                        {
                            "username": "oandres",
                            "pwd": "1234    
                        }
                """);

        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        
        // WHEN
        Mono<Void> response = gatewayFilter.filter(exchange, chain);

        // THEN
        StepVerifier.create(response).verifyComplete();

        // Verify one call
        verify(chain, times(1)).filter(exchange);
        // No interaction with jwtUtil
        verifyNoInteractions(jwtUtil);
    }
}
