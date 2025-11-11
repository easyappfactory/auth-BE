package com.wq.auth.integration

import com.wq.auth.api.controller.auth.AuthController
import com.wq.auth.api.domain.email.AuthEmailService
import com.wq.auth.api.domain.auth.AuthService
import com.wq.auth.security.jwt.JwtProperties
import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.jwt.error.JwtException
import com.wq.auth.security.jwt.error.JwtExceptionCode
import com.wq.auth.security.principal.PrincipalDetails
import io.kotest.core.spec.style.DescribeSpec
import io.kotest.extensions.spring.SpringTestExtension
import org.mockito.BDDMockito.given
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import jakarta.servlet.http.Cookie
import org.hamcrest.Matchers
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.web.servlet.MockMvc
import java.time.Duration
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import com.wq.auth.api.domain.member.entity.Role
import com.wq.auth.shared.rateLimiter.RateLimiterInterceptor
import org.mockito.Mockito.*
import org.mockito.kotlin.whenever
import org.mockito.kotlin.any

@WebMvcTest(
    controllers = [AuthController::class],
    properties = ["app.cookie.same-site=Strict"])
class AuthControllerIntegrationTest : DescribeSpec() {

    override fun extensions() = listOf(SpringTestExtension())

    @Autowired
    lateinit var mockMvc: MockMvc

    @MockitoBean
    lateinit var authService: AuthService

    @MockitoBean
    lateinit var authEmailService: AuthEmailService

    @MockitoBean
    lateinit var jwtProperties: JwtProperties

    @MockitoBean
    lateinit var jwtProvider: JwtProvider

    @MockitoBean
    lateinit var rateLimiterInterceptor: RateLimiterInterceptor

    init {

        beforeTest {
            reset(authEmailService, authService)

            whenever(rateLimiterInterceptor.preHandle(any(), any(), any())).thenReturn(true)

            // JWT 검증을 통과하도록 설정
            // validateOrThrow는 void이므로 doNothing 사용
            doNothing().whenever(jwtProvider).validateOrThrow(any())

            // getOpaqueId와 getRole Mock 설정
            whenever(jwtProvider.getOpaqueId(any())).thenReturn("opaqueId")
            whenever(jwtProvider.getRole(any())).thenReturn(Role.MEMBER)
        }

        describe("POST /api/v1/auth/members/refresh") {
            val principal = PrincipalDetails(
                opaqueId = "opaqueId",
                role = Role.MEMBER
            )

            context("Web 클라이언트에서 유효한 요청이 주어졌을 때") {
                it("성공 응답과 새로운 토큰을 반환해야 한다") {
                    // given
                    val accessToken = "valid-access-token"
                    val refreshToken = "valid-refresh-token"
                    val clientType = "web"
                    val deviceId: String? = null
                    val newAccessToken = "new-access-token"
                    val newRefreshToken = "new-refresh-token"

                    val tokenResult = AuthService.TokenResult(
                        newAccessToken,
                        newRefreshToken
                    )
                    given(authService.refreshAccessToken(refreshToken, deviceId))
                        .willReturn(tokenResult)
                    given(jwtProperties.refreshExp).willReturn(Duration.ofDays(7))

                    val requestBody = """{"deviceId": null}"""

                    // when & then
                    mockMvc.perform(
                        post("/api/v1/auth/members/refresh")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("Authorization", "Bearer $accessToken")
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(csrf()) //security 우회용
                            //.with(user("testUser").roles("USER"))
                            .with(user(principal))
                    )
                        //.andDo(print())
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("AccessToken 재발급에 성공했습니다."))
                        // web 응답은 data null, 헤더만 검증
                        .andExpect(
                            header().string(
                                "Set-Cookie",
                                Matchers.containsString("refreshToken=$newRefreshToken")
                            )
                        )
                        .andExpect(header().string("Set-Cookie", Matchers.containsString("HttpOnly")))
                        .andExpect(header().string("Set-Cookie", Matchers.containsString("SameSite=Strict")))

                    verify(authService).refreshAccessToken(refreshToken, deviceId)
                }
            }

            context("App 클라이언트에서 유효한 요청이 주어졌을 때") {
                it("성공 응답과 새로운 토큰을 반환해야 한다") {
                    // given
                    val refreshToken = "valid-refresh-token"
                    val clientType = "app"
                    val deviceId = "device123"
                    val newAccessToken = "new-access-token"
                    val newRefreshToken = "new-refresh-token"

                    val tokenResult = AuthService.TokenResult(
                        newAccessToken,
                        newRefreshToken
                    )
                    given(authService.refreshAccessToken(refreshToken, deviceId))
                        .willReturn(tokenResult)

                    val requestBody = """{"refreshToken": "$refreshToken", "deviceId": "$deviceId"}"""

                    // when & then
                    mockMvc.perform(
                        post("/api/v1/auth/members/refresh")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(csrf()) //security 우회용
                            .with(user("testUser").roles("USER"))
                    )
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("AccessToken 재발급에 성공했습니다."))
                        .andExpect(jsonPath("$.data.refreshToken").value(newRefreshToken))
                        .andExpect(header().doesNotExist("Set-Cookie"))

                    verify(authService).refreshAccessToken(refreshToken, deviceId)
                }
            }

            context("Web 클라이언트에서 서비스에서 예외가 발생했을 때") {
                it("적절한 에러 응답을 반환해야 한다") {
                    // given
                    val refreshToken = "invalid-refresh-token"
                    val clientType = "web"
                    val deviceId: String? = null
                    val requestBody = """{"deviceId": null}"""

                    given(authService.refreshAccessToken(refreshToken, deviceId))
                        .willThrow(JwtException(JwtExceptionCode.MALFORMED))

                    // when & then
                    mockMvc.perform(
                        post("/api/v1/auth/members/refresh")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(csrf()) //security 우회용
                            .with(user("testUser").roles("USER"))
                    ).andExpect(status().isUnauthorized)

                    verify(authService).refreshAccessToken(refreshToken, deviceId)
                }
            }

            context("App 클라이언트에서 서비스에서 예외가 발생했을 때") {
                it("적절한 에러 응답을 반환해야 한다") {
                    // given
                    val refreshToken = "invalid-refresh-token"
                    val clientType = "app"
                    val deviceId = "device123"
                    val requestBody = """{"refreshToken": "$refreshToken", "deviceId": "$deviceId"}"""

                    given(authService.refreshAccessToken(refreshToken, deviceId))
                        .willThrow(JwtException(JwtExceptionCode.EXPIRED))

                    // when & then
                    mockMvc.perform(
                        post("/api/v1/auth/members/refresh")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(csrf()) //security 우회용
                            .with(user("testUser").roles("USER"))
                    ).andExpect(status().isUnauthorized)

                    verify(authService).refreshAccessToken(refreshToken, deviceId)
                }
            }
        }

        describe("POST /api/v1/auth/members/email-login") {

            context("Web 클라이언트에서 유효한 요청이 주어졌을 때") {
                it("성공 응답과 토큰을 반환해야 한다") {
                    // given
                    val email = "test@example.com"
                    val verifyCode = "123456"
                    val clientType = "web"
                    val deviceId: String? = null
                    val accessToken = "access-token"
                    val refreshToken = "refresh-token"

                    val tokenResult = AuthService.TokenResult(
                        accessToken,
                        refreshToken
                    )

                    given(authService.emailLogin(email, deviceId)).willReturn(tokenResult)
                    given(jwtProperties.refreshExp).willReturn(Duration.ofDays(7))

                    val requestBody = """{"email": "$email", "verifyCode": "$verifyCode", "deviceId": null}"""

                    // when & then
                    mockMvc.perform(
                        post("/api/v1/auth/members/email-login")
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(csrf()) //security 우회용
                            .with(user("testUser").roles("USER"))
                    )
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("로그인에 성공했습니다."))
                        .andExpect(header().string("Authorization", Matchers.containsString("Bearer ")))
                        .andExpect(
                            header().string(
                                "Set-Cookie",
                                Matchers.containsString("refreshToken=$refreshToken")
                            )
                        )

                    verify(authEmailService).verifyCode(email, verifyCode)
                    verify(authService).emailLogin(email, deviceId)
                }
            }

            context("App 클라이언트에서 유효한 요청이 주어졌을 때") {
                it("성공 응답과 토큰을 반환해야 한다") {
                    // given
                    val email = "test@example.com"
                    val verifyCode = "123456"
                    val clientType = "app"
                    val deviceId = "device123"
                    val accessToken = "access-token"
                    val refreshToken = "refresh-token"

                    val tokenResult = AuthService.TokenResult(
                        accessToken,
                        refreshToken
                    )

                    given(authService.emailLogin(email, deviceId)).willReturn(tokenResult)

                    val requestBody = """{"email": "$email", "verifyCode": "$verifyCode", "deviceId": "$deviceId"}"""

                    // when & then
                    mockMvc.perform(
                        post("/api/v1/auth/members/email-login")
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(csrf()) //security 우회용
                            .with(user("testUser").roles("USER"))
                    )
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("로그인에 성공했습니다."))
                        .andExpect(jsonPath("$.data.refreshToken").value(refreshToken))
                        .andExpect(header().doesNotExist("Set-Cookie"))

                    verify(authEmailService).verifyCode(email, verifyCode)
                    verify(authService).emailLogin(email, deviceId)
                }
            }
        }

        describe("POST /api/v1/auth/members/logout") {

            context("Web 클라이언트에서 유효한 요청이 주어졌을 때") {
                it("성공 응답과 쿠키 삭제를 반환해야 한다") {
                    // given
                    val refreshToken = "valid-refresh-token"
                    val clientType = "web"
                    val principal = PrincipalDetails(
                        opaqueId = "opaqueId",
                        role = Role.MEMBER
                    )
                    val requestBody = """{}"""

                    // when & then
                    mockMvc.perform(
                        post("/api/v1/auth/members/logout")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(csrf()) //security 우회용
                            .with(user(principal))
                    )
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("로그아웃에 성공했습니다."))
                        .andExpect(jsonPath("$.data").isEmpty)
                        .andExpect(
                            header().string(
                                "Set-Cookie",
                                Matchers.containsString("refreshToken=")
                            )
                        )
                        .andExpect(header().string("Set-Cookie", Matchers.containsString("Max-Age=0")))

                    verify(authService).logout(refreshToken)
                }
            }

            context("App 클라이언트에서 유효한 요청이 주어졌을 때") {
                it("성공 응답을 반환해야 한다") {
                    // given
                    val refreshToken = "valid-refresh-token"
                    val clientType = "app"
                    val principal = PrincipalDetails(
                        opaqueId = "opaqueId",
                        role = Role.MEMBER
                    )

                    val requestBody = """{"refreshToken": "$refreshToken"}"""

                    // when & then
                    mockMvc.perform(
                        post("/api/v1/auth/members/logout")
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody)
                            .with(csrf()) //security 우회용
                            .with(user(principal))
                    )
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("로그아웃에 성공했습니다."))
                        .andExpect(jsonPath("$.data").isEmpty)
                        .andExpect(header().doesNotExist("Set-Cookie"))

                    verify(authService).logout(refreshToken)
                }
            }
        }
    }
}