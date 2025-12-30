package demo.api_gateway.Unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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
        when(chain.filter(any(ServerWebExchange.class)))
            .thenReturn(Mono.empty());
        Mono<Void> response = gatewayFilter.filter(exchange, chain);

        // THEN
        StepVerifier.create(response).verifyComplete();

        // Verify one call
        verify(chain, times(1)).filter(exchange);
        // No interaction with jwtUtil
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void filter_ProtectedPath_Unauthorized_WithoutToken(){
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/v1/user/all")
            .build();
        
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // WHEN
        Mono<Void> response = gatewayFilter.filter(exchange, chain);

        // THEN
        StepVerifier.create(response).verifyComplete();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verify(chain, never()).filter(any());
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void filter_ProtectedPath_Authorized_WithValidToken(){
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/v1/user/all")
            .header(HttpHeaders.AUTHORIZATION, "Bearer 123")
            .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // WHEN
        when(jwtUtil.isTokenExpired("123"))
            .thenReturn(false);
        when(chain.filter(any(ServerWebExchange.class)))
            .thenReturn(Mono.empty());

        Mono<Void> response = gatewayFilter.filter(exchange, chain);

        // THEN
        StepVerifier.create(response).verifyComplete();
        verify(jwtUtil, times(1)).isTokenExpired("123");
        verify(chain, times(1)).filter(exchange);
    }

    @Test
    public void filter_ProtectedPath_Unauthorized_ExpiredToken(){
        // Given
        MockServerHttpRequest request = MockServerHttpRequest
            .get("/v1/user/all")
            .header(HttpHeaders.AUTHORIZATION, "Bearer 123")
            .build();

        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        // WHEN
        when(jwtUtil.isTokenExpired("123"))
            .thenReturn(true);

        Mono<Void> response = gatewayFilter.filter(exchange, chain);

        // THEN
        StepVerifier.create(response).verifyComplete();
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verify(jwtUtil, times(1)).isTokenExpired("123");
        verify(chain, never()).filter(any());
    }
}