package com.wq.auth.api.controller.member

import com.wq.auth.api.controller.member.response.UserInfoResponseDto
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.member.MemberService
import com.wq.auth.security.annotation.AuthenticatedApi
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
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*
import java.util.concurrent.TimeUnit

@Tag(name = "회원", description = "유저 정보 조회등 회원 관련 API")
@RestController
class MemberController(
    private val memberService: MemberService,
) {

    @Operation(
        summary = "현재 로그인한 사용자 정보 조회",
        description = "로그인한 사용자의 닉네임과 이메일 정보를 반환합니다."
    )
    @ApiResponses(
        value = [
            ApiResponse(
                responseCode = "200",
                description = "조회 성공",
                content = [Content(schema = Schema(implementation = SuccessResponse::class))]
            ),
            ApiResponse(
                responseCode = "401",
                description = "인증 실패 또는 로그인 필요",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            ),
            ApiResponse(
                responseCode = "500",
                description = "회원 정보 조회에 실패했습니다.",
                content = [Content(schema = Schema(implementation = FailResponse::class))]
            )
        ]
    )
    @RateLimit(limit = 30, duration = 1, timeUnit = TimeUnit.MINUTES)
    @GetMapping("/api/v1/auth/members/user-info")
    @AuthenticatedApi
    fun getUserInfo(@AuthenticationPrincipal principalDetail: PrincipalDetails): SuccessResponse<UserInfoResponseDto> {
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
