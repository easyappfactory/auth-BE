package com.wq.auth.api.controller.internal

import com.wq.auth.api.domain.member.MemberService
import com.wq.auth.web.common.response.CommonResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/internal-api/v1/members")
class InternalMemberController(
    private val memberService: MemberService,
    @Value("\${app.internal.secret}") private val internalSecret: String,
) {

    @GetMapping("/{userId}")
    fun getUserInfo(
        @PathVariable userId: String,
        @RequestHeader("X-Internal-Secret") secret: String,
    ): CommonResponse<UserInfoResponse> {
        if (secret != internalSecret) {
            throw SecurityException("내부 API 접근 권한이 없습니다.")
        }
        val userInfo = memberService.getUserInfo(userId)
        return CommonResponse.success(data = UserInfoResponse(
            userId = userInfo.userId,
            email = userInfo.email,
            nickname = userInfo.nickname,
        ))
    }

    data class UserInfoResponse(
        val userId: String,
        val email: String,
        val nickname: String,
    )
}
