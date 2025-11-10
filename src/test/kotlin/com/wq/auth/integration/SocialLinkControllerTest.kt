package com.wq.auth.integration

import com.fasterxml.jackson.databind.ObjectMapper
import com.wq.auth.api.controller.auth.SocialLoginController
import com.wq.auth.api.domain.auth.SocialLinkService
import com.wq.auth.api.domain.auth.SocialLoginService
import com.wq.auth.api.domain.member.entity.Role
import com.wq.auth.api.domain.oauth.error.SocialLoginException
import com.wq.auth.api.domain.oauth.error.SocialLoginExceptionCode
import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.principal.PrincipalDetails
import com.wq.auth.shared.rateLimiter.RateLimiterInterceptor
import io.kotest.core.spec.style.DescribeSpec
import io.kotest.extensions.spring.SpringTestExtension
import jakarta.servlet.http.Cookie
import org.mockito.BDDMockito.given
import org.mockito.kotlin.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/**
 * 소셜 계정 연동 Controller 단위 테스트 (Kotest + Mockito)
 */
@WebMvcTest(controllers = [SocialLoginController::class])
class SocialLinkControllerTest : DescribeSpec() {

    override fun extensions() = listOf(SpringTestExtension())

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var objectMapper: ObjectMapper

    @MockitoBean
    lateinit var socialLoginService: SocialLoginService

    @MockitoBean
    lateinit var socialLinkService: SocialLinkService

    @MockitoBean
    lateinit var jwtProvider: JwtProvider

    @MockitoBean
    lateinit var rateLimiterInterceptor: RateLimiterInterceptor

    init {

        beforeTest {
            reset(socialLinkService, socialLoginService)

            whenever(rateLimiterInterceptor.preHandle(any(), any(), any())).thenReturn(true)

            // JWT 검증을 통과하도록 설정
            // validateOrThrow는 void이므로 doNothing 사용
            doNothing().whenever(jwtProvider).validateOrThrow(any())

            // getOpaqueId와 getRole Mock 설정
            whenever(jwtProvider.getOpaqueId(any())).thenReturn("opaqueId")
            whenever(jwtProvider.getRole(any())).thenReturn(Role.MEMBER)
        }

        describe("POST /api/v1/auth/link/{provider}") {

            val baseUri = "/api/v1/auth/link"
            val refreshToken = "valid-refresh-token"
            val clientType = "web"
            val accessToken = "valid-access-token"

            val principal = PrincipalDetails(
                opaqueId = "opaqueId",
                role = Role.MEMBER
            )

            context("Google 계정 연동 - 신규 연동 성공") {
                it("성공 응답을 반환해야 한다") {
                    // Given
                    val requestBody = SocialLinkRequestForTest(
                        authCode = "google_auth_code_123",
                        codeVerifier = "pkce_verifier_123"
                    )

                    // When & Then
                    mockMvc.perform(
                        post("$baseUri/google")
                            .header("Authorization", "Bearer $accessToken")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(requestBody))
                            .with(csrf())
                            //.with(user("testUser").roles("USER"))
                            .with(user(principal))
                    )
                        .andDo {
                            println("Status: ${it.response.status}")
                            println("Content: ${it.response.contentAsString}")
                        }
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("Google 계정 연동이 완료되었습니다"))

                    verify(socialLinkService).processSocialLink(any(), any())
                }
            }

            context("카카오 계정 연동 - 병합 성공") {
                it("성공 응답을 반환해야 한다") {
                    // Given
                    val requestBody = SocialLinkRequestForTest(
                        authCode = "kakao_auth_code_456",
                        codeVerifier = "pkce_verifier_456"
                    )

                    // When & Then
                    mockMvc.perform(
                        post("$baseUri/kakao")
                            .header("Authorization", "Bearer $accessToken")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(requestBody))
                            .with(csrf())
                            .with(user(principal))
                    )
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("카카오 계정 연동이 완료되었습니다"))

                    verify(socialLinkService).processSocialLink(any(), any())
                }
            }

            context("네이버 계정 연동 - state 파라미터 포함 성공") {
                it("성공 응답을 반환해야 한다") {
                    // Given
                    val requestBody = SocialLinkRequestForTest(
                        authCode = "naver_auth_code_789",
                        state = "random_state_string",
                        codeVerifier = "any_code"
                    )

                    // When & Then
                    mockMvc.perform(
                        post("$baseUri/naver")
                            .header("Authorization", "Bearer $accessToken")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(requestBody))
                            .with(csrf())
                            .with(user(principal))
                    )
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("네이버 계정 연동이 완료되었습니다"))

                    verify(socialLinkService).processSocialLink(any(), any())
                }
            }

            context("네이버 계정 연동 - state 불일치/만료로 실패") {
                it("400 Bad Request를 반환해야 한다") {
                    // Given
                    given(socialLinkService.processSocialLink(any(), any()))
                        .willThrow(SocialLoginException(SocialLoginExceptionCode.NAVER_INVALID_STATE))

                    val requestBody = SocialLinkRequestForTest(
                        authCode = "valid_code",
                        state = "invalid_state",
                        codeVerifier = "any_code"
                    )

                    // When & Then
                    mockMvc.perform(
                        post("$baseUri/naver")
                            .header("Authorization", "Bearer $accessToken")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(requestBody))
                            .with(csrf())
                            .with(user(principal))
                    )
                        .andExpect(status().isBadRequest)
                }
            }

            context("소셜 계정 연동(네이버) - 인증되지 않은 사용자") {
                it("401 Unauthorized를 반환해야 한다") {
                    // Given
                    val requestBody = SocialLinkRequestForTest(
                        authCode = "any_code",
                        state = "any_state",
                        codeVerifier = "any_code"
                    )

                    // When & Then
                    mockMvc.perform(
                        post("$baseUri/naver")
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(requestBody))
                            .with(csrf())
                    )
                        .andExpect(status().isUnauthorized)
                }
            }

            context("소셜 계정 연동(구글) - 유효하지 않은 인가 코드") {
                it("400 Bad Request를 반환해야 한다") {
                    // Given
                    given(socialLinkService.processSocialLink(any(), any()))
                        .willThrow(SocialLoginException(SocialLoginExceptionCode.GOOGLE_INVALID_AUTHORIZATION_CODE))

                    val requestBody = SocialLinkRequestForTest(
                        authCode = "invalid_auth_code",
                        codeVerifier = "any_verifier"
                    )

                    // When & Then
                    mockMvc.perform(
                        post("$baseUri/google")
                            .header("Authorization", "Bearer $accessToken")
                            .cookie(Cookie("refreshToken", refreshToken))
                            .header("X-Client-Type", clientType)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(requestBody))
                            .with(csrf())
                            .with(user(principal))
                    )
                        .andExpect(status().isBadRequest)
                }
            }
        }
    }
}

// 테스트에서 사용하는 DTO (요청 본문 구조에 맞게 정의)
data class SocialLinkRequestForTest(
    val authCode: String,
    val codeVerifier: String,
    val state: String? = null
)