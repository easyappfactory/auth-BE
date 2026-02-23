package com.wq.auth.api.controller

import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.annotation.AuthenticatedApi
import com.wq.auth.security.annotation.PublicApi
import com.wq.auth.web.common.response.CommonResponse
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/**
 * Security 테스트용 컨트롤러
 * 개발 및 테스트 환경에서 JWT 인증 동작을 확인하기 위한 엔드포인트 제공
 * todo: 나중에 제거 예정
 */
@RestController
class TestSecurityController(
    private val jwtProvider: JwtProvider
) {

    @PublicApi
    @GetMapping("/api/public/test")
    fun publicTestEndpoint(): CommonResponse<Map<String, String>> {
        val data = mapOf(
            "endpoint" to "/api/public/test",
            "accessLevel" to "PUBLIC",
            "description" to "누구나 접근 가능한 공개 API"
        )
        return CommonResponse.success("공개 API 접근 성공", data)
    }

    @AuthenticatedApi
    @GetMapping("/api/test")
    fun authenticatedEndpoint(): CommonResponse<Map<String, String>> {
        val data = mapOf(
            "endpoint" to "/api/test",
            "accessLevel" to "AUTHENTICATED",
            "description" to "로그인한 사용자만 접근 가능한 API"
        )
        return CommonResponse.success("인증된 사용자 API 접근 성공", data)
    }

    @PublicApi
    @GetMapping("/api/public/token")
    fun generateTestToken(
        @RequestParam(defaultValue = "550e8400-e29b-41d4-a716-446655440000") opaqueId: String,
    ): CommonResponse<Map<String, String>> {
        val token = jwtProvider.createAccessToken(opaqueId)
        val data = mapOf(
            "token" to token,
            "opaqueId" to opaqueId,
            "usage" to "Authorization: Bearer $token"
        )
        return CommonResponse.success("JWT 토큰 발급 성공", data)
    }
}
