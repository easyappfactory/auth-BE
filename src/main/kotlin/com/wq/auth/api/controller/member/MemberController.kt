package com.wq.auth.api.controller.member

import com.wq.auth.api.controller.member.response.UserInfoResponseDto
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.member.MemberService
import com.wq.auth.security.annotation.AuthenticatedApi
import com.wq.auth.security.principal.PrincipalDetails
import com.wq.auth.web.common.response.Responses
import com.wq.auth.web.common.response.SuccessResponse
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*

@Tag(name = "회원", description = "유저 정보 조회등 회원 관련 API")
@RestController
class MemberController(
    private val memberService: MemberService,
) : MemberApiDocs {

    @GetMapping("/api/v1/auth/members/user-info")
    @AuthenticatedApi
    override fun getUserInfo(@AuthenticationPrincipal principalDetail: PrincipalDetails): SuccessResponse<UserInfoResponseDto> {
        val (nickname, email, linkedProviders) = memberService.getUserInfo(principalDetail.opaqueId)
        val resp = UserInfoResponseDto(nickname, email, linkedProviders)
        return Responses.success(message = "회원 정보 조회 성공", data = resp)
    }

    @GetMapping("/api/v1/members")
    fun getAll(): SuccessResponse<List<MemberEntity>> =
        Responses.success("회원 목록 조회 성공", memberService.getAll())

    @GetMapping("/api/v1/members/{id}")
    fun getById(@PathVariable id: Long): SuccessResponse<MemberEntity?> =
        Responses.success("회원 조회 성공", memberService.getById(id))

    @PostMapping("/api/v1/members")
    fun create(@RequestBody member: MemberEntity): SuccessResponse<MemberEntity> =
        Responses.success("회원 생성 성공", memberService.create(member))

    @DeleteMapping("/api/v1/members/{id}")
    fun delete(@PathVariable id: Long): SuccessResponse<Void> {
        memberService.delete(id)
        return Responses.success("회원 삭제 성공")
    }

    @PutMapping("/api/v1/members/{id}/nickname")
    fun updateNickname(
        @PathVariable id: Long,
        @RequestBody payload: Map<String, String>
    ): SuccessResponse<MemberEntity?> {
        val newNickname = payload["nickname"] ?: throw IllegalArgumentException("닉네임은 필수입니다")
        return Responses.success("닉네임 변경 성공", memberService.updateNickname(id, newNickname))
    }

}
