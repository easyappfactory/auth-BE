package com.wq.auth.api.controller.member.response

import com.wq.auth.api.domain.auth.entity.ProviderType

data class UserInfoResponseDto(
    val nickname: String,
    val email: String,
    val linkedProviders: List<ProviderType>
)
