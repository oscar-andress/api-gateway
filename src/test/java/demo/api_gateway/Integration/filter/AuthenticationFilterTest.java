package demo.api_gateway.Integration.filter;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AuthenticationFilterTest {
    
    @Autowired
    private WebTestClient webTestClient;

    private WireMockServer wireMockServer;

    @BeforeAll
    void startWireMockServer(){
        wireMockServer = new WireMockServer(8080);
        wireMockServer.start();
        WireMock.configureFor("localhost", 8080);
    }

    @AfterAll
    void stopWireMock() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @BeforeEach
    void resetWireMock() {
        wireMockServer.resetAll();
    }

    @Test
    public void publicEndPoint_PostLogin_Success_withoutToken(){
        // GIVEN
        stubFor(post(urlEqualTo("/v1/auth/register"))
            .willReturn(aResponse()
                .withStatus(201)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                        {
                            "username": "oandres"    
                        }
                        """)));
        String registerRequest = """
                {
                    "username": "oandres",
                    "pwd": "1234"
                }
                """;

        // WHEN & THEN
        webTestClient.post()
            .uri("/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(registerRequest)
            .exchange()
            .expectStatus().isCreated()
            .expectBody()
            .jsonPath("$.username").isEqualTo("oandres");
    }

    @Test
    public void protectedEndPoint_PostLogin_Authorized_withToken(){
        // GIVEN
        stubFor(post(urlEqualTo("/v1/auth/login"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.OK.value())
                .withHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .withBody("""
                        {
                            "username": "oandres",
                            "jwt": "abc"    
                        }
                        """)));

        String loginRequest = """
                {
                    "username": "oandres",
                    "pwd": "1234"
                }
                """;
        
        // WHEN & THEN
        webTestClient.post()
            .uri("/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(loginRequest)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.jwt").isEqualTo("abc");
    }
}
