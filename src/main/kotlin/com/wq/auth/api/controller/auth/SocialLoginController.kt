package com.wq.auth.api.controller.auth

import com.wq.auth.api.controller.auth.request.*
import com.wq.auth.api.domain.auth.SocialLinkService
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.SocialLoginService
import com.wq.auth.security.annotation.AuthenticatedApi
import com.wq.auth.security.annotation.PublicApi
import com.wq.auth.security.principal.PrincipalDetails
import com.wq.auth.shared.rateLimiter.annotation.RateLimit
import com.wq.auth.web.common.response.FailResponse
import com.wq.auth.web.common.response.Responses
import com.wq.auth.web.common.response.SuccessResponse
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.servlet.http.HttpServletResponse
import jakarta.validation.Valid
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*
import java.time.Duration
import java.util.concurrent.TimeUnit

/**
 * 소셜 로그인 컨트롤러
 *
 * 소셜 로그인 관련 API 엔드포인트를 제공합니다.
 * - Google, 카카오, 네이버 등 소셜 제공자를 통한 로그인 처리
 * - 인가 코드를 받아 JWT 토큰 발급
 * 로그인된 상태에서 다른 소셜 제공자 계정을 연동하는 API 엔드포인트를 제공합니다.
 * - Google, 카카오, 네이버 등 소셜 제공자 계정 연동
 * - 기존 연동 계정이 있는 경우 자동 병합
 */
@Tag(name = "소셜 로그인", description = "Google, 카카오, 네이버 등 소셜 제공자를 통한 로그인 API, 로그인된 상태에서 다른 소셜 제공자 계정을 연동하는 API")
@RestController
class SocialLoginController(
    private val socialLoginService: SocialLoginService,
    private val socialLinkService: SocialLinkService,

    @Value("\${app.cookie.secure:false}")
    private val cookieSecure: Boolean,

    @Value("\${app.cookie.same-site:Strict}")
    private val cookieSameSite: String
) {

    /**
     * 범용 소셜 로그인 처리
     *
     * 프론트엔드에서 소셜 제공자로부터 받은 인가 코드를 사용하여
     * 사용자 정보를 조회하고 JWT 토큰을 발급합니다.
     *
     * @param request 소셜 로그인 요청 (인가 코드, 제공자 타입 등)
     * @return JWT 토큰과 사용자 정보가 포함된 응답
     */
    @Operation(
        summary = "범용 소셜 로그인",
        description = """
            프론트엔드에서 소셜 제공자로부터 받은 인가 코드를 사용하여 사용자 정보를 조회하고 JWT 토큰을 발급합니다.
            
            **redirectUri 파라미터:**
            - 선택사항: 미제공시 properties에 설정된 기본값 사용
            - 각 소셜 제공자의 OAuth2 설정에서 승인된 리다이렉트 URI와 일치해야 함
            - 프론트엔드 환경별로 다른 URI 사용 가능 (개발/스테이징/프로덕션)
            
            **토큰 반환 방식:**
            - Access Token: Authorization 헤더에 Bearer 방식으로 반환
            - Refresh Token: HttpOnly 쿠키로 설정 (XSS 공격 방지)
            
            **지원 소셜 제공자:**
            - GOOGLE: Google OAuth2
            - KAKAO: 카카오 OAuth2
            - NAVER: 네이버 OAuth2
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "로그인 성공 - Authorization 헤더에 Bearer 토큰, HttpOnly 쿠키에 리프레시 토큰 설정",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "400",
                description = "잘못된 요청 (필수 필드 누락, 잘못된 형식 등)",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "인가 코드가 유효하지 않거나 만료됨",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "소셜 제공자 API 호출 실패 또는 서버 내부 오류",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @PublicApi("소셜 로그인")
    @PostMapping("/api/v1/auth/social/login")
    fun socialLogin(
        @Valid @RequestBody request: SocialLoginRequestDto,
        response: HttpServletResponse
    ): SuccessResponse<Void> {
        val loginResult = socialLoginService.processSocialLogin(request.toDomain())

        // RefreshToken을 HttpOnly 쿠키에 설정
        setRefreshTokenCookie(response, loginResult.refreshToken)

        // Authorization 헤더에 AccessToken 설정
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer ${loginResult.accessToken}")

        return Responses.success("소셜 로그인이 완료되었습니다")
    }

    /**
     * Google 소셜 로그인 (편의 메서드)
     *
     * Google 전용 엔드포인트로, providerType을 별도로 지정하지 않아도 됩니다.
     *
     * @param authorizationCode Google 인가 코드
     * @param redirectUri 리다이렉트 URI (선택사항)
     * @return JWT 토큰과 사용자 정보가 포함된 응답
     */
    @Operation(
        summary = "Google 소셜 로그인",
        description = """
            Google 전용 편의 메서드로, providerType을 별도로 지정하지 않아도 됩니다.
            
            **사용 방법:**
            1. 프론트엔드에서 Google OAuth2 인증 URL로 사용자를 리다이렉트
            2. 사용자가 Google에서 인증 완료 후 받은 인가 코드(code)를 이 API로 전송
            3. 백엔드에서 Google API를 통해 사용자 정보 조회 후 JWT 토큰 발급
            
            **redirectUri 파라미터:**
            - 선택사항: 미제공시 properties에 설정된 기본값 사용
            - Google OAuth2 설정의 승인된 리다이렉트 URI와 일치해야 함
            - 프론트엔드 환경별로 다른 URI 사용 가능
            
            **토큰 반환 방식:**
            - Access Token: Authorization 헤더에 Bearer 방식으로 반환
            - Refresh Token: HttpOnly 쿠키로 설정 (XSS 공격 방지)
            
            **쿠키 설정:**
            - HttpOnly: JavaScript 접근 불가 (XSS 방지)
            - Path=/: 모든 경로에서 사용 가능
            - Max-Age=1209600: 14일 만료
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "Google 로그인 성공 - Authorization 헤더에 Bearer 토큰, HttpOnly 쿠키에 리프레시 토큰 설정",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "400",
                description = "인가 코드(code) 파라미터가 누락되거나 잘못된 형식",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "Google 인가 코드가 유효하지 않거나 만료됨",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "Google API 호출 실패 또는 서버 내부 오류",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 10, duration = 10, timeUnit = TimeUnit.MINUTES)
    @PublicApi("Google 소셜 로그인")
    @PostMapping("/api/v1/auth/google/login")
    fun googleLogin(
        @Valid @RequestBody request: GoogleSocialLoginRequestDto,
        response: HttpServletResponse
    ): SuccessResponse<Void> {

        val loginResult = socialLoginService.processSocialLogin(request.toDomain())

        // RefreshToken을 HttpOnly 쿠키에 설정
        setRefreshTokenCookie(response, loginResult.refreshToken)

        // Authorization 헤더에 AccessToken 설정
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer ${loginResult.accessToken}")

        return Responses.success("Google 로그인이 완료되었습니다")
    }

    /**
     * 카카오 소셜 로그인 (편의 메서드)
     *
     * 카카오 전용 엔드포인트로, providerType을 별도로 지정하지 않아도 됩니다.
     *
     * @param request 카카오 소셜 로그인 요청
     * @param response HTTP 응답 객체
     * @return JWT 토큰과 사용자 정보가 포함된 응답
     */
    @Operation(
        summary = "카카오 소셜 로그인",
        description = """
            카카오 전용 편의 메서드로, providerType을 별도로 지정하지 않아도 됩니다.
            
            **사용 방법:**
            1. 프론트엔드에서 카카오 OAuth2 인증 URL로 사용자를 리다이렉트
            2. 사용자가 카카오에서 인증 완료 후 받은 인가 코드(code)를 이 API로 전송
            3. 백엔드에서 카카오 API를 통해 사용자 정보 조회 후 JWT 토큰 발급
            
            **리다이렉트 URI:**
            - 환경변수(properties)에 설정된 기본값 사용
            - 카카오 OAuth2 설정의 승인된 리다이렉트 URI와 일치해야 함
            
            **PKCE (Proof Key for Code Exchange):**
            - 카카오는 PKCE를 지원하지만 선택사항
            - 보안 강화를 위해 사용 권장
            
            **토큰 반환 방식:**
            - Access Token: Authorization 헤더에 Bearer 방식으로 반환
            - Refresh Token: HttpOnly 쿠키로 설정 (XSS 공격 방지)
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "카카오 로그인 성공 - Authorization 헤더에 Bearer 토큰, HttpOnly 쿠키에 리프레시 토큰 설정",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "400",
                description = "인가 코드(code) 파라미터가 누락되거나 잘못된 형식",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "카카오 인가 코드가 유효하지 않거나 만료됨",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "카카오 API 호출 실패 또는 서버 내부 오류",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 10, duration = 10, timeUnit = TimeUnit.MINUTES)
    @PublicApi("카카오 소셜 로그인")
    @PostMapping("/api/v1/auth/kakao/login")
    fun kakaoLogin(
        @Valid @RequestBody request: KakaoSocialLoginRequestDto,
        response: HttpServletResponse
    ): SuccessResponse<Void> {

        val loginResult = socialLoginService.processSocialLogin(request.toDomain())

        // RefreshToken을 HttpOnly 쿠키에 설정
        setRefreshTokenCookie(response, loginResult.refreshToken)

        // Authorization 헤더에 AccessToken 설정
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer ${loginResult.accessToken}")

        return Responses.success("카카오 로그인이 완료되었습니다")
    }

    /**
     * Naver 소셜 로그인 (편의 메서드)
     *
     * Naver 전용 엔드포인트로, providerType을 별도로 지정하지 않아도 됩니다.
     *
     * @param authorizationCode Naver 인가 코드
     * @param redirectUri 리다이렉트 URI (선택사항)
     * @return JWT 토큰과 사용자 정보가 포함된 응답
     */
    @Operation(
        summary = "Naver 소셜 로그인",
        description = """
            Naver 전용 편의 메서드로, providerType을 별도로 지정하지 않아도 됩니다.
            
            **사용 방법:**
            1. 프론트엔드에서 Naver OAuth2 인증 URL로 사용자를 리다이렉트
            2. 사용자가 Naver 인증 완료 후 받은 인가 코드(code)를 이 API로 전송
            3. 백엔드에서 Naver API를 통해 사용자 정보 조회 후 JWT 토큰 발급
            
            **redirectUri 파라미터:**
            - 선택사항: 미제공시 properties에 설정된 기본값 사용
            - Naver OAuth2 설정의 승인된 리다이렉트 URI와 일치해야 함
            - 프론트엔드 환경별로 다른 URI 사용 가능
            
            **토큰 반환 방식:**
            - Access Token: Authorization 헤더에 Bearer 방식으로 반환
            - Refresh Token: HttpOnly 쿠키로 설정 (XSS 공격 방지)
            
            **쿠키 설정:**
            - HttpOnly: JavaScript 접근 불가 (XSS 방지)
            - Path=/: 모든 경로에서 사용 가능
            - Max-Age=1209600: 14일 만료
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "Naver 로그인 성공 - Authorization 헤더에 Bearer 토큰, HttpOnly 쿠키에 리프레시 토큰 설정",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "400",
                description = "인가 코드(code) 파라미터가 누락되거나 잘못된 형식",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "Naver 인가 코드가 유효하지 않거나 만료됨",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "Naver API 호출 실패 또는 서버 내부 오류",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 10, duration = 10, timeUnit = TimeUnit.MINUTES)
    @PublicApi("Naver 소셜 로그인")
    @PostMapping("/api/v1/auth/naver/login")
    fun naverLogin(
        @Valid @RequestBody request: NaverSocialLoginRequestDto,
        response: HttpServletResponse
    ): SuccessResponse<Void> {
        val loginResult = socialLoginService.processSocialLogin(request.toDomain())

        // RefreshToken을 HttpOnly 쿠키에 설정
        setRefreshTokenCookie(response, loginResult.refreshToken)

        // Authorization 헤더에 AccessToken 설정
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer ${loginResult.accessToken}")

        return Responses.success("Naver 로그인이 완료되었습니다")
    }

    /**
     * Google 계정 연동
     *
     * 현재 로그인된 회원에게 Google 계정을 연동합니다.
     *
     * @param user 현재 로그인된 사용자 정보 (Security Context에서 자동 주입)
     * @param request Google 소셜 로그인 요청
     * @return 연동 성공 응답
     */
    @Operation(
        summary = "Google 계정 연동",
        description = """
            현재 로그인된 회원에게 Google 계정을 연동합니다.
            
            **사용 방법:**
            1. 프론트엔드에서 Google OAuth2 인증 URL로 사용자를 리다이렉트
            2. 사용자가 Google에서 인증 완료 후 받은 인가 코드(code)를 이 API로 전송
            3. 백엔드에서 Google API를 통해 사용자 정보 조회 후 계정 연동
            
            **연동 프로세스:**
            - 연동 계정이 없는 경우: AuthProvider만 추가
            - 연동 계정이 있는 경우: 두 계정 자동 병합 (기존 회원 정보 유지)
            
            **인증 요구사항:**
            - Authorization 헤더에 유효한 JWT 토큰 필요
            - 토큰은 재발급되지 않으며 기존 토큰 그대로 사용
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "Google 계정 연동 성공",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "400",
                description = "인가 코드(code) 파라미터가 누락되거나 잘못된 형식",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "인증되지 않은 사용자 또는 Google 인가 코드가 유효하지 않음",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "Google API 호출 실패 또는 서버 내부 오류",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 5, duration = 10, timeUnit = TimeUnit.MINUTES)
    @AuthenticatedApi
    @PostMapping("/api/v1/auth/link/google")
    fun linkGoogleAccount(
        @AuthenticationPrincipal principalDetail: PrincipalDetails,
        @Valid @RequestBody request: GoogleSocialLinkRequestDto
    ): SuccessResponse<Void> {
        val serviceRequest = SocialLinkRequestDto(
            authCode = request.authCode,
            codeVerifier = request.codeVerifier,
            providerType = ProviderType.GOOGLE,
        )

        socialLinkService.processSocialLink(principalDetail.opaqueId, serviceRequest.toDomain())

        return Responses.success("Google 계정 연동이 완료되었습니다")
    }

    /**
     * 카카오 계정 연동
     *
     * 현재 로그인된 회원에게 카카오 계정을 연동합니다.
     *
     * @param user 현재 로그인된 사용자 정보 (Security Context에서 자동 주입)
     * @param request 카카오 소셜 로그인 요청
     * @return 연동 성공 응답
     */
    @Operation(
        summary = "카카오 계정 연동",
        description = """
            현재 로그인된 회원에게 카카오 계정을 연동합니다.
            
            **사용 방법:**
            1. 프론트엔드에서 카카오 OAuth2 인증 URL로 사용자를 리다이렉트
            2. 사용자가 카카오에서 인증 완료 후 받은 인가 코드(code)를 이 API로 전송
            3. 백엔드에서 카카오 API를 통해 사용자 정보 조회 후 계정 연동
            
            **연동 프로세스:**
            - 연동 계정이 없는 경우: AuthProvider만 추가
            - 연동 계정이 있는 경우: 두 계정 자동 병합 (기존 회원 정보 유지)
            
            **PKCE (Proof Key for Code Exchange):**
            - 카카오는 PKCE를 지원하지만 선택사항
            - 보안 강화를 위해 사용 권장
            
            **인증 요구사항:**
            - Authorization 헤더에 유효한 JWT 토큰 필요
            - 토큰은 재발급되지 않으며 기존 토큰 그대로 사용
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "카카오 계정 연동 성공",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "400",
                description = "인가 코드(code) 파라미터가 누락되거나 잘못된 형식",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "인증되지 않은 사용자 또는 카카오 인가 코드가 유효하지 않음",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "카카오 API 호출 실패 또는 서버 내부 오류",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 5, duration = 10, timeUnit = TimeUnit.MINUTES)
    @AuthenticatedApi
    @PostMapping("/api/v1/auth/link/kakao")
    fun linkKakaoAccount(
        @AuthenticationPrincipal principalDetail: PrincipalDetails,
        @Valid @RequestBody request: KakaoSocialLinkRequestDto
    ): SuccessResponse<Void> {
        val serviceRequest = SocialLinkRequestDto(
            authCode = request.authCode,
            codeVerifier = request.codeVerifier,
            providerType = ProviderType.KAKAO,
        )

        socialLinkService.processSocialLink(principalDetail.opaqueId, serviceRequest.toDomain())

        return Responses.success("카카오 계정 연동이 완료되었습니다")
    }

    /**
     * 네이버 계정 연동
     *
     * 현재 로그인된 회원에게 네이버 계정을 연동합니다.
     *
     * @param user 현재 로그인된 사용자 정보 (Security Context에서 자동 주입)
     * @param request 네이버 소셜 로그인 요청
     * @return 연동 성공 응답
     */
    @Operation(
        summary = "네이버 계정 연동",
        description = """
            현재 로그인된 회원에게 네이버 계정을 연동합니다.
            
            **사용 방법:**
            1. 프론트엔드에서 네이버 OAuth2 인증 URL로 사용자를 리다이렉트
            2. 사용자가 네이버에서 인증 완료 후 받은 인가 코드(code)를 이 API로 전송
            3. 백엔드에서 네이버 API를 통해 사용자 정보 조회 후 계정 연동
            
            **연동 프로세스:**
            - 연동 계정이 없는 경우: AuthProvider만 추가
            - 연동 계정이 있는 경우: 두 계정 자동 병합 (기존 회원 정보 유지)
            
            **State 파라미터:**
            - 네이버는 CSRF 방지를 위해 state 파라미터 사용
            - 프론트엔드에서 생성한 state 값을 전달해야 함
            
            **인증 요구사항:**
            - Authorization 헤더에 유효한 JWT 토큰 필요
            - 토큰은 재발급되지 않으며 기존 토큰 그대로 사용
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "네이버 계정 연동 성공",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "400",
                description = "인가 코드(code) 또는 state 파라미터가 누락되거나 잘못된 형식",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "인증되지 않은 사용자 또는 네이버 인가 코드가 유효하지 않음",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "네이버 API 호출 실패 또는 서버 내부 오류",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 5, duration = 10, timeUnit = TimeUnit.MINUTES)
    @AuthenticatedApi
    @PostMapping("/api/v1/auth/link/naver")
    fun linkNaverAccount(
        @AuthenticationPrincipal principalDetail: PrincipalDetails,
        @Valid @RequestBody request: NaverSocialLinkRequestDto
    ): SuccessResponse<Void> {
        val serviceRequest = SocialLinkRequestDto(
            authCode = request.authCode,
            codeVerifier = request.codeVerifier,
            state = request.state,
            providerType = ProviderType.NAVER,
        )

        socialLinkService.processSocialLink(principalDetail.opaqueId, serviceRequest.toDomain())

        return Responses.success("네이버 계정 연동이 완료되었습니다")
    }

    /**
     * RefreshToken을 HttpOnly 쿠키로 설정합니다.
     *
     * Spring Boot 3.x의 ResponseCookie를 사용하여 현대적이고 안전한 쿠키를 생성합니다.
     * - HttpOnly: JavaScript 접근 불가 (XSS 방지)
     * - Secure: HTTPS에서만 전송 (프로덕션 환경)
     * - SameSite: CSRF 공격 방지
     * - MaxAge: 14일 (리프레시 토큰 만료 시간과 동일)
     *
     * @param response HTTP 응답 객체
     * @param refreshToken 리프레시 토큰
     */
    private fun setRefreshTokenCookie(response: HttpServletResponse, refreshToken: String) {
        val cookie = ResponseCookie.from("refreshToken", refreshToken)
            .httpOnly(true)                              // XSS 공격 방지
            .secure(cookieSecure)                                  // 환경별 설정 (개발: false, 프로덕션: true)
            .path("/")                                      // 모든 경로에서 쿠키 사용 가능
            .maxAge(Duration.ofDays(14))          // 14일 만료
            .sameSite(cookieSameSite)                              // CSRF 공격 방지 (Strict/Lax/None)
            .build()

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString())
    }
}
