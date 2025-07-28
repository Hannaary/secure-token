package com.example.securetoken.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

@Service
public class TokenService {

    protected final KeyPair keyPair;

    /**
     * Конструктор: создаёт пару RSA-ключей для подписи и шифрования
     */
    public TokenService() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            keyPair = keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Ошибка генерации пары ключей RSA", e);
        }
    }

    /**
     * Создаёт JWT, подписывает его (JWS) и шифрует (JWE)
     * @param payload полезные данные
     * @return зашифрованный JWT в строковом виде
     */
    public String generateEncryptedJwt(String payload) {
        try {
            JWSSigner signer = new RSASSASigner(keyPair.getPrivate());
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject("secure-payload")
                    .claim("data", payload)
                    .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.RS256),
                    claimsSet
            );
            signedJWT.sign(signer);

            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                            .contentType("JWT").build(),
                    new Payload(signedJWT)
            );

            RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) keyPair.getPublic());
            jweObject.encrypt(encrypter);

            return jweObject.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при создании и шифровании JWT", e);
        }
    }

    /**
     * Расшифровывает и проверяет подпись JWT, возвращает полезную нагрузку
     * @param token зашифрованный JWT
     * @return полезные данные из токена (claim "data")
     */
    public String decryptAndValidateJwt(String token) {
        try {
            JWEObject jweObject = JWEObject.parse(token);
            RSADecrypter decrypter = new RSADecrypter(keyPair.getPrivate());
            jweObject.decrypt(decrypter);

            JWTClaimsSet claims = getJwtClaimsSet(jweObject);
            if (new Date().after(claims.getExpirationTime())) {
                throw new RuntimeException("Срок действия токена истёк");
            }

            return claims.getStringClaim("data");
        } catch (Exception e) {
            throw new RuntimeException("Ошибка проверки токена: " + e.getMessage(), e);
        }
    }

    /**
     * Извлекает claims из SignedJWT и проверяет его подпись
     * @param jweObject расшифрованный объект JWE
     * @return claims (полезные данные JWT)
     * @throws JOSEException ошибка подписи
     * @throws ParseException ошибка синтаксиса JWT
     */
    private JWTClaimsSet getJwtClaimsSet(JWEObject jweObject) throws JOSEException, ParseException {
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
        if (signedJWT == null) {
            throw new RuntimeException("Токен не содержит SignedJWT");
        }

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) keyPair.getPublic());
        if (!signedJWT.verify(verifier)) {
            throw new RuntimeException("Ошибка проверки подписи");
        }

        return signedJWT.getJWTClaimsSet();
    }
}