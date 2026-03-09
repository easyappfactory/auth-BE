package com.wq.auth.api.controller.auth

import com.wq.auth.api.controller.auth.request.EmailLoginLinkRequestDto
import com.wq.auth.api.controller.auth.request.EmailLoginRequestDto
import com.wq.auth.api.controller.auth.request.LogoutRequestDto
import com.wq.auth.api.controller.auth.request.RefreshAccessTokenRequestDto
import com.wq.auth.api.controller.auth.response.LoginResponseDto
import com.wq.auth.api.controller.auth.response.RefreshAccessTokenResponseDto
import com.wq.auth.api.domain.auth.AuthService
import com.wq.auth.api.domain.email.AuthEmailService
import com.wq.auth.api.domain.member.MemberService
import com.wq.auth.security.JwtAuthenticationFilter
import com.wq.auth.security.annotation.AuthenticatedApi
import com.wq.auth.security.annotation.PublicApi
import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.jwt.error.JwtException
import com.wq.auth.security.jwt.error.JwtExceptionCode
import com.wq.auth.security.principal.PrincipalDetails
import com.wq.auth.shared.config.CookieFactory
import com.wq.auth.shared.rateLimiter.annotation.RateLimit
import com.wq.auth.web.common.response.CommonResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import jakarta.validation.Valid
import org.springframework.http.HttpHeaders
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*
import java.util.concurrent.TimeUnit

@Tag(name = "인증/인가", description = "로그인, 로그아웃 등 인증/인가 관련 API")
@RestController
class AuthController(
    private val authService: AuthService,
    private val emailService: AuthEmailService,
    private val memberService: MemberService,
    private val cookieFactory: CookieFactory,
    private val jwtProvider: JwtProvider,
) {
    private val log = KotlinLogging.logger {}

    @Operation(
        summary = "이메일 로그인",
        description = "회원 가입을 한 사용자 라면, 회원 이메일로 로그인하고 회원 가입을 하지 않은 사용자라면 회원가입 후 AccessToken과 RefreshToken을 발급합니다."
    )

    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "로그인 성공",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "이메일 인증 실패",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "회원 정보를 저장하는데 실패했습니다.",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 5, duration = 15, timeUnit = TimeUnit.MINUTES)
    @PostMapping("/api/v1/auth/members/email-login")
    @PublicApi
    fun emailLogin(
        response: HttpServletResponse,
        @RequestHeader("X-Client-Type", required = true) clientType: String,
        @RequestBody req: EmailLoginRequestDto,

        ): CommonResponse<LoginResponseDto> {
        emailService.verifyCode(req.email, req.verifyCode)
        val (accessToken, newRefreshToken) = authService.emailLogin(
            req.email,
            deviceId = req.deviceId,
        )

        val accessTokenCookie = cookieFactory.createAccessTokenCookie(accessToken)
        val refreshTokenCookie = cookieFactory.createRefreshTokenCookie(newRefreshToken)
        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())

        if (clientType == "web") {
            return CommonResponse.success(message = "로그인에 성공했습니다.", data = null)
        }

        //앱
        val resp = LoginResponseDto.forApp(
            refreshToken = newRefreshToken
        )
        return CommonResponse.success(message = "로그인에 성공했습니다.", data = resp)
    }


    /**
     * 이메일 인증 코드 확인 및 계정 연동
     *
     * 사용자가 입력한 인증 코드를 확인하고 이메일 계정을 연동합니다.
     *
     * @param principalDetail 현재 로그인된 사용자 정보 (Security Context에서 자동 주입)
     * @param request 이메일 인증 확인 요청
     * @return 계정 연동 성공 응답
     */
    @Operation(
        summary = "이메일 인증 코드 확인 및 계정 연동",
        description = """
            사용자가 입력한 인증 코드를 확인하고 이메일 계정을 연동합니다.
            
            **사용 방법:**
            1. 이메일로 받은 6자리 인증 코드를 입력
            2. 인증 성공 시 이메일 계정 연동 완료
            
            **연동 프로세스:**
            - 인증 코드 유효성 확인 (만료 시간, 코드 일치 여부)
            - AuthProvider 엔티티에 EMAIL 타입 추가
            - 인증 코드 삭제
            
            **인증 요구사항:**
            - `accessToken` HttpOnly 쿠키에 유효한 JWT 토큰 필요
            - 토큰은 재발급되지 않으며 기존 토큰 그대로 사용
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "이메일 계정 연동 성공",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "400",
                description = "인증 코드가 존재하지 않거나, 만료되었거나, 일치하지 않음",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "인증되지 않은 사용자",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "서버 내부 오류",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 5, duration = 10, timeUnit = TimeUnit.MINUTES)
    @AuthenticatedApi
    @PostMapping("/api/v1/auth/link/email-login")
    fun verifyEmailLink(
        @AuthenticationPrincipal principalDetail: PrincipalDetails,
        @Valid @RequestBody request: EmailLoginLinkRequestDto
    ): CommonResponse<Void> {
        authService.processEmailLoginLink(principalDetail.opaqueId, request.toDomain())
        return CommonResponse.success("이메일 계정이 성공적으로 연동되었습니다.")
    }

    @Operation(
        summary = "로그아웃",
        description = "RefreshToken을 DB에서 삭제하여 로그아웃합니다."
    )

    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "로그아웃 성공",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "로그아웃에 실패했습니다.",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 10, duration = 1, timeUnit = TimeUnit.MINUTES)
    @PostMapping("/api/v1/auth/members/logout")
    @PublicApi
    fun logout(
        @CookieValue(name = "refreshToken", required = false) refreshToken: String?,
        response: HttpServletResponse,
        @RequestHeader(name = "X-Client-Type", required = true) clientType: String,
        @RequestBody req: LogoutRequestDto?
    ): CommonResponse<Void?> {

        val currentRefreshToken = when (clientType) {
            "web" -> refreshToken
            "app" -> req?.refreshToken
            else -> null
        }

        authService.logout(currentRefreshToken)

        if (clientType == "web") {
            val expireAccessTokenCookie = cookieFactory.expireAccessTokenCookie()
            val expireRefreshTokenCookie = cookieFactory.expireRefreshTokenCookie()
            response.addHeader(HttpHeaders.SET_COOKIE, expireAccessTokenCookie.toString())
            response.addHeader(HttpHeaders.SET_COOKIE, expireRefreshTokenCookie.toString())
        }
        //앱
        return CommonResponse.success(message = "로그아웃에 성공했습니다.", data = null)
    }

    @Operation(
        summary = "액세스 토큰 재발급",
        description = "유효한 리프레시 토큰을 이용해 새로운 액세스 토큰과 리프레시 토큰을 발급합니다."
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "액세스 토큰 재발급 성공",
                content = [Content(
                    mediaType = "application/json",
                    schema = Schema(implementation = RefreshAccessTokenResponseDto::class)
                )]
            ),
            ApiResponse(
                responseCode = "400",
                description = "잘못된 요청, 인증 토큰이 없음",
                content = [Content(
                    mediaType = "application/json",
                    schema = Schema(implementation = CommonResponse::class)
                )]
            ),
            ApiResponse(
                responseCode = "401",
                description = "유효하지 않은 토큰, 만료된 토큰, 유효하지 않은 서명, 지원되지 않는 토큰",
                content = [Content(
                    mediaType = "application/json",
                    schema = Schema(implementation = CommonResponse::class)
                )]
            ),
            ApiResponse(
                responseCode = "500",
                description = "refreshToken 조회 실패",
                content = [Content(
                    mediaType = "application/json",
                    schema = Schema(implementation = CommonResponse::class)
                )]
            )
        ]
    )
    @RateLimit(limit = 20, duration = 1, timeUnit = TimeUnit.HOURS)
    @PostMapping("/api/v1/auth/members/refresh")
    @PublicApi
    fun refreshAccessToken(
        request: HttpServletRequest, // 헤더/쿠키에서 이전 AT를 읽기 위함
        @CookieValue(name = "refreshToken", required = false) refreshToken: String?,
        @RequestHeader("X-Client-Type") clientType: String,
        response: HttpServletResponse,
        @RequestBody req: RefreshAccessTokenRequestDto?,
    ): CommonResponse<RefreshAccessTokenResponseDto> {

        val currentRefreshToken : String? = if(clientType == "web") {
            refreshToken
        } else {
            req?.refreshToken
        }

        if (currentRefreshToken.isNullOrBlank()) {
            throw JwtException(JwtExceptionCode.TOKEN_MISSING)
        }

        val (accessToken, newRefreshToken) = authService.refreshAccessToken(
            currentRefreshToken, req?.deviceId
        )

        val accessTokenCookie = cookieFactory.createAccessTokenCookie(accessToken)
        val refreshTokenCookie = cookieFactory.createRefreshTokenCookie(newRefreshToken)
        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())

        if (clientType == "web") {
            return CommonResponse.success(message = "AccessToken 재발급에 성공했습니다.", data = null)
        }

        //앱
        val resp = RefreshAccessTokenResponseDto.forApp(
            refreshToken = newRefreshToken
        )
        return CommonResponse.success(message = "AccessToken 재발급에 성공했습니다.", data = resp)

    }

    @Operation(
        summary = "토큰 introspect",
        description = """
            API Gateway 연동용 엔드포인트입니다. 요청에 포함된 Access Token을 검증하고, 성공 시 응답 헤더에 사용자 정보를 담아 반환합니다.
            
            **토큰 탐색 우선순위:**
            1. `accessToken` HttpOnly 쿠키
               - 쿠키 값이 비어있으면 401을 반환합니다.
            2. `Authorization: Bearer <token>` 헤더 (쿠키가 없을 때만 사용)
            
            **토큰 반환 방식:**
            - Access Token: HttpOnly 쿠키(`accessToken`)
            - Refresh Token: HttpOnly 쿠키(`refreshToken`)
            - 기존 Authorization 헤더는 더 이상 사용하지 않습니다.
            
            **사일런트 리프레시 (Silent Refresh):**
            - Access Token이 만료되었거나 남은 유효 시간이 5분(300초) 미만이면 `refreshToken` 쿠키로 자동 재발급을 시도합니다.
            - 재발급 성공 시 응답의 `Set-Cookie`로 새 토큰을 내려주며 FE/사용자 개입이 불필요합니다.
            - 재발급 실패(리프레시 토큰 만료·오류) 시 기존 쿠키를 모두 삭제하고 401을 반환합니다.
            
            **성공 응답 헤더:**
            - `X-User-Id`: 사용자 UUID (opaqueId)
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "인트로스펙트 성공 (X-User-Id 헤더 포함). AT가 임박한 경우 Set-Cookie로 새 토큰도 포함됩니다.",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "토큰 없음, 빈 쿠키, 리프레시 토큰 만료·오류 등 인증 실패. 쿠키가 존재하던 경우 해당 쿠키는 제거됩니다.",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 60, duration = 1, timeUnit = TimeUnit.MINUTES)
    @PublicApi
    @GetMapping("/api/v1/auth/introspect")
    fun introspect(
        request: HttpServletRequest,
        response: HttpServletResponse,
    ) {
        val token = JwtAuthenticationFilter.extractToken(request)
        // 쿠키·헤더 모두 없거나, accessToken 쿠키가 빈 값인 경우 401
        if (token.isNullOrBlank()) {
            throw JwtException(JwtExceptionCode.TOKEN_MISSING)
        }

        // AT가 만료(-1)되었거나 남은 시간이 5분(300초) 미만이면 사일런트 리프레시 시도
        val remainingSeconds = jwtProvider.getRemainingTimeSeconds(token)
        val opaqueId: String = if (remainingSeconds < 300) {
            val refreshToken = request.cookies?.firstOrNull { it.name == "refreshToken" }?.value

            if (refreshToken.isNullOrBlank()) {
                clearAuthCookies(response)
                throw JwtException(JwtExceptionCode.TOKEN_MISSING)
            }

            try {
                // 만료된 AT에서도 claims를 읽어 deviceId를 추출합니다.
                val claims = jwtProvider.getClaimsEvenIfExpired(token)
                val deviceId = claims["deviceId"] as? String

                val tokenResult = authService.refreshAccessToken(refreshToken, deviceId)

                response.addHeader(HttpHeaders.SET_COOKIE, cookieFactory.createAccessTokenCookie(tokenResult.accessToken).toString())
                response.addHeader(HttpHeaders.SET_COOKIE, cookieFactory.createRefreshTokenCookie(tokenResult.refreshToken).toString())

                log.debug { "사일런트 리프레시 성공 (remainingSeconds=$remainingSeconds)" }

                jwtProvider.getOpaqueId(tokenResult.accessToken)
            } catch (e: Exception) {
                log.warn { "사일런트 리프레시 실패: ${e.message}" }
                clearAuthCookies(response)
                throw JwtException(JwtExceptionCode.EXPIRED)
            }
        } else {
            jwtProvider.getOpaqueId(token)
        }

        response.setHeader("X-User-Id", opaqueId)
    }

    /**
     * accessToken, refreshToken HttpOnly 쿠키를 즉시 만료시킵니다.
     */
    private fun clearAuthCookies(response: HttpServletResponse) {
        response.addHeader(HttpHeaders.SET_COOKIE, cookieFactory.expireAccessTokenCookie().toString())
        response.addHeader(HttpHeaders.SET_COOKIE, cookieFactory.expireRefreshTokenCookie().toString())
    }
}
