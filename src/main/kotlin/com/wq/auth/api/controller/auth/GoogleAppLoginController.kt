package com.wq.auth.api.controller.auth

import com.wq.auth.api.controller.auth.request.GoogleAppLoginRequestDto
import com.wq.auth.api.controller.auth.response.SocialLoginResponseDto
import com.wq.auth.api.domain.auth.GoogleAppLoginService
import com.wq.auth.security.annotation.PublicApi
import com.wq.auth.shared.rateLimiter.annotation.RateLimit
import com.wq.auth.web.common.response.CommonResponse
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.media.Content
import io.swagger.v3.oas.annotations.media.Schema
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.responses.ApiResponses
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.util.concurrent.TimeUnit

/**
 * 안드로이드 앱 전용 Google 로그인 컨트롤러
 *
 * 웹의 인가 코드(Code) 방식과 달리, 앱에서 Google Credential Manager로
 * 발급받은 ID Token을 직접 검증하여 JWT(AT/RT)를 JSON Body로 반환합니다.
 */
@Tag(name = "Google 앱 로그인", description = "안드로이드 앱 전용 Google ID Token 로그인 API")
@RestController
class GoogleAppLoginController(
    private val googleAppLoginService: GoogleAppLoginService,
) {

    @Operation(
        summary = "Google 앱 로그인",
        description = """
            안드로이드 앱 전용 Google 로그인 엔드포인트입니다.

            앱은 Google Credential Manager를 통해 발급받은 **ID Token**을 그대로 전달합니다.
            서버는 Google 라이브러리를 사용해 ID Token을 직접 검증하며, 구글 서버와의 추가 통신이 불필요합니다.

            **응답:**
            - 인증 성공 시 자체 JWT(accessToken, refreshToken)를 JSON Body에 반환합니다.
        """
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200", description = "로그인 성공",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "400", description = "idToken 누락 또는 필수 필드 오류",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "401", description = "유효하지 않은 Google ID Token",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
            ApiResponse(
                responseCode = "429", description = "Rate Limit 초과 (10분에 10회)",
                content = [Content(schema = Schema(implementation = CommonResponse::class))]
            ),
        ]
    )
    @RateLimit(limit = 10, duration = 10, timeUnit = TimeUnit.MINUTES)
    @PublicApi("Google 앱 로그인")
    @PostMapping("/api/v1/auth/google/login/app")
    fun loginWithApp(
        @Valid @RequestBody request: GoogleAppLoginRequestDto,
    ): CommonResponse<SocialLoginResponseDto> {
        val loginResult = googleAppLoginService.login(request.idToken)
        return CommonResponse.success(
            message = "Google 로그인이 완료되었습니다",
            data = SocialLoginResponseDto(
                accessToken = loginResult.accessToken,
                refreshToken = loginResult.refreshToken,
            )
        )
    }
}
