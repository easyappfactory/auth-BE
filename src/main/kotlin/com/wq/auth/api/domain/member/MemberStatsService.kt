package com.wq.auth.api.domain.member

import com.wq.auth.api.domain.member.entity.MemberEntity
import org.springframework.scheduling.annotation.Async
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDateTime

@Service
class MemberStatsService(
    private val memberRepository: MemberRepository
) {
    /**
     * 마지막 로그인 시간 비동기 업데이트
     * 로그인 응답 속도를 개선하기 위해 별도 스레드에서 처리합니다.
     */
    @Async
    @Transactional
    fun updateLastLoginAtAsync(memberId: Long) {
        val member = memberRepository.findById(memberId).orElse(null) ?: return
        member.lastLoginAt = LocalDateTime.now()
        memberRepository.save(member)
    }
}
