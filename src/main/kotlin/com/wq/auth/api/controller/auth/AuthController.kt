package com.wq.auth.api.controller.auth

import com.wq.auth.api.controller.auth.request.EmailLoginLinkRequestDto
import com.wq.auth.api.controller.auth.request.EmailLoginRequestDto
import com.wq.auth.api.controller.auth.request.LogoutRequestDto
import com.wq.auth.api.controller.auth.request.RefreshAccessTokenRequestDto
import com.wq.auth.api.controller.auth.response.LoginResponseDto
import com.wq.auth.api.controller.auth.response.RefreshAccessTokenResponseDto
import com.wq.auth.api.domain.auth.AuthService
import com.wq.auth.api.domain.email.AuthEmailService
import com.wq.auth.security.annotation.AuthenticatedApi
import com.wq.auth.security.annotation.PublicApi
import com.wq.auth.security.jwt.JwtProperties
import com.wq.auth.security.principal.PrincipalDetails
import com.wq.auth.shared.rateLimiter.annotation.RateLimit
import com.wq.auth.web.common.response.BaseResponse
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
import java.util.concurrent.TimeUnit

@Tag(name = "인증/인가", description = "로그인, 로그아웃 등 인증/인가 관련 API")
@RestController
class AuthController(
    private val authService: AuthService,
    private val emailService: AuthEmailService,
    private val jwtProperties: JwtProperties,

    @Value("\${app.cookie.secure:false}")
    private val cookieSecure: Boolean,

    @Value("\${app.cookie.same-site:Strict}")
    private val cookieSameSite: String,
) {

    @Operation(
        summary = "이메일 로그인",
        description = "회원 가입을 한 사용자 라면, 회원 이메일로 로그인하고 회원 가입을 하지 않은 사용자라면 회원가입 후 AccessToken과 RefreshToken을 발급합니다."
    )

    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "로그인 성공",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "이메일 인증 실패",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "회원 정보를 저장하는데 실패했습니다.",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 5, duration = 15, timeUnit = TimeUnit.MINUTES)
    @PostMapping("api/v1/auth/members/email-login")
    @PublicApi
    fun emailLogin(
        response: HttpServletResponse,
        @RequestHeader("X-Client-Type", required = true) clientType: String,
        @RequestBody req: EmailLoginRequestDto,

        ): SuccessResponse<LoginResponseDto> {
        emailService.verifyCode(req.email, req.verifyCode)
        val (accessToken, newRefreshToken) = authService.emailLogin(
            req.email,
            deviceId = req.deviceId,
        )

        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer ${accessToken}")

        if (clientType == "web") {
            val refreshCookie = ResponseCookie.from("refreshToken", newRefreshToken)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(jwtProperties.refreshExp.toSeconds())
                .domain(".easyappfactory.com")  // 모든 서브도메인 포함
                .sameSite("Lax")  //SSO 리다이렉트 시 쿠키 전송을 위해 Lax 권장
                .build()
            response.addHeader("Set-Cookie", refreshCookie.toString())

            return Responses.success(message = "로그인에 성공했습니다.", data = null)
        }

        //앱
        val resp = LoginResponseDto.forApp(
            refreshToken = newRefreshToken
        )
        return Responses.success(message = "로그인에 성공했습니다.", data = resp)
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
            - Authorization 헤더에 유효한 JWT 토큰 필요
            - 토큰은 재발급되지 않으며 기존 토큰 그대로 사용
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "이메일 계정 연동 성공",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "400",
                description = "인증 코드가 존재하지 않거나, 만료되었거나, 일치하지 않음",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "인증되지 않은 사용자",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "서버 내부 오류",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 5, duration = 10, timeUnit = TimeUnit.MINUTES)
    @AuthenticatedApi
    @PostMapping("/api/v1/auth/link/email-login")
    fun verifyEmailLink(
        @AuthenticationPrincipal principalDetail: PrincipalDetails,
        @Valid @RequestBody request: EmailLoginLinkRequestDto
    ): SuccessResponse<Void> {
        authService.processEmailLoginLink(principalDetail.opaqueId, request.toDomain())
        return Responses.success("이메일 계정이 성공적으로 연동되었습니다.")
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
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "로그아웃에 실패했습니다.",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 10, duration = 1, timeUnit = TimeUnit.MINUTES)
    @PostMapping("api/v1/auth/members/logout")
    @PublicApi
    fun logout(
        @CookieValue(name = "refreshToken", required = false) refreshToken: String?,
        response: HttpServletResponse,
        @RequestHeader(name = "X-Client-Type", required = true) clientType: String,
        @RequestBody req: LogoutRequestDto?
    ): SuccessResponse<Void?> {

        val currentRefreshToken = when (clientType) {
            "web" -> refreshToken
            "app" -> req?.refreshToken
            else -> null
        }

        authService.logout(currentRefreshToken)

        if (clientType == "web") {
            val refreshCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(0)
                .sameSite(cookieSameSite)
                .build()
            response.addHeader("Set-Cookie", refreshCookie.toString())

        }
        //앱
        return Responses.success(message = "로그아웃에 성공했습니다.", data = null)
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
                description = "잘못된 요청, 인증 토큰이 없음, Authorization 헤더는 'Bearer <token>' 형식이어야 합니다.",
                content = [Content(
                    mediaType = "application/json",
                    schema = Schema(implementation = BaseResponse::class)
                )]
            ),
            ApiResponse(
                responseCode = "401",
                description = "유효하지 않은 토큰, 만료된 토큰, 유효하지 않은 서명, 지원되지 않는 토큰",
                content = [Content(
                    mediaType = "application/json",
                    schema = Schema(implementation = BaseResponse::class)
                )]
            ),
            ApiResponse(
                responseCode = "500",
                description = "refreshToken 조회 실패",
                content = [Content(
                    mediaType = "application/json",
                    schema = Schema(implementation = BaseResponse::class)
                )]
            )
        ]
    )
    @RateLimit(limit = 20, duration = 1, timeUnit = TimeUnit.HOURS)
    @PostMapping("api/v1/auth/members/refresh")
    @PublicApi
    fun refreshAccessToken(
        @CookieValue(name = "refreshToken", required = false) refreshToken: String,
        @RequestHeader("X-Client-Type") clientType: String,
        response: HttpServletResponse,
        @RequestBody req: RefreshAccessTokenRequestDto?,
    ): SuccessResponse<RefreshAccessTokenResponseDto> {
        
        val currentRefreshToken : String?
        if(clientType == "web") {
            currentRefreshToken = refreshToken
        } else {
            currentRefreshToken = req?.refreshToken
        }
        val (accessToken, newRefreshToken) = authService.refreshAccessToken(
            currentRefreshToken!!, req?.deviceId,
        )
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer ${accessToken}")

        if (clientType == "web") {

            val refreshCookie = ResponseCookie.from("refreshToken", newRefreshToken)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(jwtProperties.refreshExp.toSeconds())
                .sameSite(cookieSameSite)
                .build()
            response.addHeader("Set-Cookie", refreshCookie.toString())
            
            return Responses.success(message = "AccessToken 재발급에 성공했습니다.", data = null)
        }
        
        //앱
        val resp = RefreshAccessTokenResponseDto.forApp(
            refreshToken = newRefreshToken
        )
        return Responses.success(message = "AccessToken 재발급에 성공했습니다.", data = resp)

    }

}
