package com.wq.auth.integration

import com.wq.auth.api.controller.member.MemberController
import com.wq.auth.api.domain.member.MemberService
import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.principal.PrincipalDetails
import com.wq.auth.shared.config.CookieFactory
import com.wq.auth.shared.rateLimiter.RateLimiterInterceptor
import io.kotest.core.spec.style.DescribeSpec
import io.kotest.extensions.spring.SpringExtension
import org.hamcrest.Matchers
import org.mockito.kotlin.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.http.ResponseCookie
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*

@WebMvcTest(
    controllers = [MemberController::class],
    properties = ["app.cookie.same-site=Strict"]
)
@Import(WebMvcTestSecurityConfig::class)
class MemberWithdrawControllerTest : DescribeSpec() {

    @Autowired
    lateinit var mockMvc: MockMvc

    @MockitoBean
    lateinit var memberService: MemberService

    @MockitoBean
    lateinit var cookieFactory: CookieFactory

    @MockitoBean
    lateinit var jwtProvider: JwtProvider

    @MockitoBean
    lateinit var rateLimiterInterceptor: RateLimiterInterceptor

    override val extensions = listOf(SpringExtension())

    init {
        beforeTest {
            reset(memberService, cookieFactory)
            whenever(rateLimiterInterceptor.preHandle(any(), any(), any())).thenReturn(true)
            doNothing().whenever(jwtProvider).validateOrThrow(any())
            whenever(jwtProvider.getOpaqueId(any())).thenReturn("test-opaque-id")
        }

        describe("DELETE /api/v1/auth/members/me") {

            context("인증된 web 클라이언트 요청") {
                it("탈퇴 성공 후 쿠키 만료 Set-Cookie 헤더를 반환한다") {
                    val principal = PrincipalDetails(opaqueId = "test-opaque-id")

                    whenever(cookieFactory.expireAccessTokenCookie()).thenReturn(
                        ResponseCookie.from("accessToken", "").maxAge(0).build()
                    )
                    whenever(cookieFactory.expireRefreshTokenCookie()).thenReturn(
                        ResponseCookie.from("refreshToken", "").maxAge(0).build()
                    )

                    mockMvc.perform(
                        delete("/api/v1/auth/members/me")
                            .header("X-Client-Type", "web")
                            .with(csrf())
                            .with(user(principal))
                    )
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("회원 탈퇴 성공"))
                        .andExpect(header().string("Set-Cookie", Matchers.containsString("Max-Age=0")))

                    verify(memberService).withdraw("test-opaque-id", "web")
                    verify(cookieFactory).expireAccessTokenCookie()
                    verify(cookieFactory).expireRefreshTokenCookie()
                }
            }

            context("인증된 app 클라이언트 요청") {
                it("탈퇴 성공하고 Set-Cookie 헤더가 없다") {
                    val principal = PrincipalDetails(opaqueId = "test-opaque-id")

                    mockMvc.perform(
                        delete("/api/v1/auth/members/me")
                            .header("X-Client-Type", "app")
                            .with(csrf())
                            .with(user(principal))
                    )
                        .andExpect(status().isOk)
                        .andExpect(jsonPath("$.success").value(true))
                        .andExpect(jsonPath("$.message").value("회원 탈퇴 성공"))
                        .andExpect(header().doesNotExist("Set-Cookie"))

                    verify(memberService).withdraw("test-opaque-id", "app")
                    verify(cookieFactory, never()).expireAccessTokenCookie()
                    verify(cookieFactory, never()).expireRefreshTokenCookie()
                }
            }

            context("미인증 요청") {
                it("401 Unauthorized를 반환한다") {
                    mockMvc.perform(
                        delete("/api/v1/auth/members/me")
                            .header("X-Client-Type", "web")
                            .with(csrf())
                    )
                        .andExpect(status().isUnauthorized)
                }
            }
        }
    }
}
