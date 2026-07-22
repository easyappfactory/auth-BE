package com.wq.auth.api.controller.internal

import com.wq.auth.api.domain.member.MemberService
import com.wq.auth.web.common.response.CommonResponse
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController

@RestController
class InternalMemberController(
    private val memberService: MemberService,
    @Value("\${app.internal.secret}") private val internalSecret: String,
) {

    companion object {
        private val log = LoggerFactory.getLogger(InternalMemberController::class.java)
    }

    @GetMapping("/internal-api/v1/members/{userId}")
    fun getUserInfo(
        @PathVariable userId: String,
        @RequestHeader("X-Internal-Secret") secret: String,
    ): CommonResponse<UserInfoResponse> {
        log.info("[internal-api] getUserInfo 요청 - userId={}", userId)
        if (secret != internalSecret) {
            log.warn("[internal-api] 인증 실패 - X-Internal-Secret 불일치, userId={}", userId)
            throw SecurityException("내부 API 접근 권한이 없습니다.")
        }
        val userInfo = memberService.getUserInfo(userId)
        log.info("[internal-api] getUserInfo 성공 - userId={}", userId)
        return CommonResponse.success(data = UserInfoResponse(
            userId = userInfo.userId,
            email = userInfo.email,
            nickname = userInfo.nickname,
            phoneNumber = userInfo.phoneNumber,
        ))
    }

    data class UserInfoResponse(
        val userId: String,
        val email: String,
        val nickname: String,
        val phoneNumber: String?,
    )
}
