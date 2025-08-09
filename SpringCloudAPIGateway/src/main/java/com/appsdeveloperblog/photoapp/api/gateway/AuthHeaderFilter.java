package com.appsdeveloperblog.photoapp.api.gateway;

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import reactor.core.publisher.Mono;

@Component
public class AuthHeaderFilter extends AbstractGatewayFilterFactory<AuthHeaderFilter.Config> {

    private static String TOKEN_SECRET="token.secret";

    @Autowired
    Environment env;

    public static class Config {

    }

    public AuthHeaderFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No AuthorizationHeader", HttpStatus.UNAUTHORIZED);
            }
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            String jwt = authHeader.replace("Bearer", "");

            if (!isValid(jwt)) {
                return onError(exchange, "Token is not Valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        };

    }

    private boolean isValid(String jwt) {
        // TODO Auto-generated method stub

        boolean returnValue=true;
        Jws<Claims> claims= null;
        String subject=null;
        String tokenSecret=env.getProperty(TOKEN_SECRET);
        @SuppressWarnings("null")
        byte[] secretKeyBytes=Base64.getEncoder().encode(tokenSecret.getBytes());
        SecretKey secretKey= new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());

        JwtParser jwtParser=Jwts.parserBuilder().setSigningKey(secretKey).build();
        try {
            claims = jwtParser.parseClaimsJws(jwt);
            subject=claims.getBody().getSubject();
           
        } catch (Exception e) {
            returnValue = false;
        }
        if(subject == null || subject.isEmpty()) {
            returnValue = false;
        }

        return returnValue;
    }

    private Mono<Void> onError(ServerWebExchange exchange, String string, HttpStatus unauthorized) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(unauthorized);
        return response.setComplete();
    }

}
