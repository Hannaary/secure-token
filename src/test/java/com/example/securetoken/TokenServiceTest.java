package com.example.securetoken;

import com.example.securetoken.service.TokenService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;

class TokenServiceTest {
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenService();
    }

    @Test
    void testGenerateAndValidateJwt() {
        String payload = "секретные_данные";

        String token = tokenService.generateEncryptedJwt(payload);
        assertNotNull(token, "Токен не должен быть null");

        String result = tokenService.decryptAndValidateJwt(token);
        assertEquals(payload, result, "Расшифрованные данные не совпадают с исходными");
    }

    @Test
    void testExpiredTokenThrowsException() {
        TokenService shortLivedService = new TokenService() {
            @Override
            public String generateEncryptedJwt(String payload) {
                try {
                    // Генерируем токен, который сразу истекает
                    JWTClaimsSet claims = new JWTClaimsSet.Builder()
                            .claim("data", payload)
                            .expirationTime(new java.util.Date(System.currentTimeMillis() - 1000)) // уже истёк
                            .build();

                    SignedJWT signedJWT = new SignedJWT(
                            new JWSHeader(JWSAlgorithm.RS256),
                            claims
                    );
                    signedJWT.sign(new RSASSASigner(keyPair.getPrivate()));

                    JWEObject jweObject = new JWEObject(
                            new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                    .contentType("JWT").build(),
                            new Payload(signedJWT)
                    );
                    jweObject.encrypt(new RSAEncrypter((RSAPublicKey) keyPair.getPublic()));
                    return jweObject.serialize();

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        String expiredToken = shortLivedService.generateEncryptedJwt("устаревшее");

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> shortLivedService.decryptAndValidateJwt(expiredToken));

        assertTrue(ex.getMessage().contains("Срок действия токена истёк"));
    }
}