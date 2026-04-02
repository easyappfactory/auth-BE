package com.wq.auth.api.controller.member.response

import com.wq.auth.api.domain.auth.entity.ProviderType

data class UserInfoResponseDto(
    /** 사용자 식별자 (UUID v7, opaqueId) */
    val userId: String,
    val nickname: String,
    val email: String,
    val linkedProviders: List<ProviderType>
)
