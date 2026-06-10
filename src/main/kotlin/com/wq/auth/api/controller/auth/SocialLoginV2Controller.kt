package com.wq.auth.api.controller.auth

import com.wq.auth.api.controller.auth.request.GoogleSocialLoginRequestDto
import com.wq.auth.api.controller.auth.request.KakaoSocialLoginRequestDto
import com.wq.auth.api.controller.auth.request.NaverSocialLoginRequestDto
import com.wq.auth.api.controller.auth.request.SocialLoginRequestDto
import com.wq.auth.api.controller.auth.request.toDomain
import com.wq.auth.api.controller.auth.response.SocialLoginResponseDto
import com.wq.auth.api.domain.auth.SocialLoginService
import com.wq.auth.api.domain.auth.response.SocialLoginResult
import com.wq.auth.security.annotation.PublicApi
import com.wq.auth.shared.config.CookieFactory
import com.wq.auth.shared.rateLimiter.annotation.RateLimit
import com.wq.auth.web.common.response.CommonResponse
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.servlet.http.HttpServletResponse
import jakarta.validation.Valid
import org.springframework.http.HttpHeaders
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController
import java.util.concurrent.TimeUnit

/**
 * 소셜 로그인 V2 컨트롤러
 *
 * X-Client-Id 헤더를 기반으로 웹/앱 응답을 분기합니다.
 * - web (X-Client-Id: web): HttpOnly 쿠키로 토큰 반환
 * - app (X-Client-Id: easy-snap-app 등): JSON body에 accessToken / refreshToken 반환
 *
 * 기존 V1(/api/v1/auth)은 유지되며, 신규 클라이언트는 이 V2를 사용하세요.
 */
@Tag(name = "소셜 로그인 V2", description = "X-Client-Id 기반 웹/앱 분기 소셜 로그인 API")
@RestController
class SocialLoginV2Controller(
    private val socialLoginService: SocialLoginService,
    private val cookieFactory: CookieFactory,
) {

    @Operation(
        summary = "범용 소셜 로그인 V2",
        description = """
            X-Client-Id 헤더 값에 따라 토큰 반환 방식이 달라집니다.

            **X-Client-Id: web**
            - Access Token: HttpOnly 쿠키(`accessToken`)
            - Refresh Token: HttpOnly 쿠키(`refreshToken`)
            - 응답 body data: null

            **X-Client-Id: {앱 식별자} (예: easy-snap-app)**
            - 쿠키 미설정
            - 응답 body data: `{ accessToken, refreshToken }`
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(responseCode = "200", description = "로그인 성공",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "400", description = "X-Client-Id 헤더 누락 또는 필수 필드 오류",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "401", description = "인가 코드 유효하지 않음",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "500", description = "소셜 제공자 API 호출 실패",
                content = [Content(schema = Schema(implementation = CommonResponse::class))])
        ]
    )
    @PublicApi("소셜 로그인 V2")
    @PostMapping("/api/v2/auth/social/login")
    fun socialLogin(
        @Valid @RequestBody request: SocialLoginRequestDto,
        @RequestHeader("X-Client-Id") clientId: String,
        response: HttpServletResponse,
    ): CommonResponse<SocialLoginResponseDto?> {
        val loginResult = socialLoginService.processSocialLogin(request.toDomain())
        return buildLoginResponse(clientId, loginResult, response, "소셜 로그인이 완료되었습니다")
    }

    @Operation(
        summary = "Google 소셜 로그인 V2",
        description = """
            X-Client-Id 헤더 값에 따라 토큰 반환 방식이 달라집니다.

            **X-Client-Id: web**
            - Access Token: HttpOnly 쿠키(`accessToken`)
            - Refresh Token: HttpOnly 쿠키(`refreshToken`)
            - 응답 body data: null

            **X-Client-Id: {앱 식별자} (예: easy-snap-app)**
            - 쿠키 미설정
            - 응답 body data: `{ accessToken, refreshToken }`

            **PKCE 필수:**
            - codeVerifier는 Google 인증 요청 시 사용한 code_verifier와 동일해야 합니다.
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(responseCode = "200", description = "Google 로그인 성공",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "400", description = "X-Client-Id 헤더 누락 또는 필수 필드 오류",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "401", description = "Google 인가 코드 유효하지 않음",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "429", description = "Rate Limit 초과 (10분에 10회)",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "500", description = "Google API 호출 실패",
                content = [Content(schema = Schema(implementation = CommonResponse::class))])
        ]
    )
    @RateLimit(limit = 10, duration = 10, timeUnit = TimeUnit.MINUTES)
    @PublicApi("Google 소셜 로그인 V2")
    @PostMapping("/api/v2/auth/google/login")
    fun googleLogin(
        @Valid @RequestBody request: GoogleSocialLoginRequestDto,
        @RequestHeader("X-Client-Id") clientId: String,
        response: HttpServletResponse,
    ): CommonResponse<SocialLoginResponseDto?> {
        val loginResult = socialLoginService.processSocialLogin(request.toDomain())
        return buildLoginResponse(clientId, loginResult, response, "Google 로그인이 완료되었습니다")
    }

    @Operation(
        summary = "카카오 소셜 로그인 V2",
        description = """
            X-Client-Id 헤더 값에 따라 토큰 반환 방식이 달라집니다.

            **X-Client-Id: web**
            - Access Token: HttpOnly 쿠키(`accessToken`)
            - Refresh Token: HttpOnly 쿠키(`refreshToken`)
            - 응답 body data: null

            **X-Client-Id: {앱 식별자} (예: easy-snap-app)**
            - 쿠키 미설정
            - 응답 body data: `{ accessToken, refreshToken }`
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(responseCode = "200", description = "카카오 로그인 성공",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "400", description = "X-Client-Id 헤더 누락 또는 필수 필드 오류",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "401", description = "카카오 인가 코드 유효하지 않음",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "429", description = "Rate Limit 초과 (10분에 10회)",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "500", description = "카카오 API 호출 실패",
                content = [Content(schema = Schema(implementation = CommonResponse::class))])
        ]
    )
    @RateLimit(limit = 10, duration = 10, timeUnit = TimeUnit.MINUTES)
    @PublicApi("카카오 소셜 로그인 V2")
    @PostMapping("/api/v2/auth/kakao/login")
    fun kakaoLogin(
        @Valid @RequestBody request: KakaoSocialLoginRequestDto,
        @RequestHeader("X-Client-Id") clientId: String,
        response: HttpServletResponse,
    ): CommonResponse<SocialLoginResponseDto?> {
        val loginResult = socialLoginService.processSocialLogin(request.toDomain())
        return buildLoginResponse(clientId, loginResult, response, "카카오 로그인이 완료되었습니다")
    }

    @Operation(
        summary = "Naver 소셜 로그인 V2",
        description = """
            X-Client-Id 헤더 값에 따라 토큰 반환 방식이 달라집니다.

            **X-Client-Id: web**
            - Access Token: HttpOnly 쿠키(`accessToken`)
            - Refresh Token: HttpOnly 쿠키(`refreshToken`)
            - 응답 body data: null

            **X-Client-Id: {앱 식별자} (예: easy-snap-app)**
            - 쿠키 미설정
            - 응답 body data: `{ accessToken, refreshToken }`
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(responseCode = "200", description = "Naver 로그인 성공",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "400", description = "X-Client-Id 헤더 누락 또는 필수 필드 오류",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "401", description = "Naver 인가 코드 유효하지 않음",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "429", description = "Rate Limit 초과 (10분에 10회)",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]),
            ApiResponse(responseCode = "500", description = "Naver API 호출 실패",
                content = [Content(schema = Schema(implementation = CommonResponse::class))])
        ]
    )
    @RateLimit(limit = 10, duration = 10, timeUnit = TimeUnit.MINUTES)
    @PublicApi("Naver 소셜 로그인 V2")
    @PostMapping("/api/v2/auth/naver/login")
    fun naverLogin(
        @Valid @RequestBody request: NaverSocialLoginRequestDto,
        @RequestHeader("X-Client-Id") clientId: String,
        response: HttpServletResponse,
    ): CommonResponse<SocialLoginResponseDto?> {
        val loginResult = socialLoginService.processSocialLogin(request.toDomain())
        return buildLoginResponse(clientId, loginResult, response, "Naver 로그인이 완료되었습니다")
    }

    /**
     * X-Client-Id 값에 따라 토큰 반환 방식을 분기합니다.
     *
     * - "web": HttpOnly 쿠키 설정, body data null
     * - 그 외 (앱 식별자): 쿠키 미설정, body에 accessToken / refreshToken 반환
     */
    private fun buildLoginResponse(
        clientId: String,
        loginResult: SocialLoginResult,
        response: HttpServletResponse,
        message: String,
    ): CommonResponse<SocialLoginResponseDto?> {
        return if (clientId == "web") {
            val accessTokenCookie = cookieFactory.createAccessTokenCookie(loginResult.accessToken)
            val refreshTokenCookie = cookieFactory.createRefreshTokenCookie(loginResult.refreshToken)
            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
            response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
            CommonResponse.success(message = message, data = null)
        } else {
            CommonResponse.success(
                message = message,
                data = SocialLoginResponseDto(
                    accessToken = loginResult.accessToken,
                    refreshToken = loginResult.refreshToken,
                )
            )
        }
    }
}
