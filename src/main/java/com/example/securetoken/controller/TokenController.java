package com.example.securetoken.controller;

import com.example.securetoken.service.TokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/token")
@Tag(name = "Token Controller", description = "Операции с зашифрованными токенами JWT")
class TokenController {

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    /**
     * Генерирует зашифрованный JWT с RSA-подписью
     * @param payload полезные данные
     * @return зашифрованный токен JWT
     */
    @PostMapping("/generate")
    @Operation(summary = "Генерация токена", description = "Создает JWE-токен с RSA-подписью", responses = {
            @ApiResponse(responseCode = "200", description = "Успешная генерация токена")
    })
    public String generateToken(@RequestBody String payload) {
        return tokenService.generateEncryptedJwt(payload);
    }

    /**
     * Проверяет зашифрованный токен, возвращает полезную нагрузку
     * @param token зашифрованный токен
     * @return расшифрованные данные (claim "data")
     */
    @PostMapping("/validate")
    @Operation(summary = "Проверка токена", description = "Расшифровка и валидация JWT-токена", responses = {
            @ApiResponse(responseCode = "200", description = "Токен валиден"),
            @ApiResponse(responseCode = "400", description = "Ошибка в токене")
    })
    public String validateToken(@RequestBody String token) {
        return tokenService.decryptAndValidateJwt(token);
    }
}