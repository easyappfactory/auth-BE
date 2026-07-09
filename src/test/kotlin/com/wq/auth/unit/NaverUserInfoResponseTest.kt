package com.wq.auth.unit

import com.wq.auth.api.external.oauth.dto.NaverUserInfo
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

class NaverUserInfoResponseTest : StringSpec({

    fun naverUserInfo(mobile: String?) = NaverUserInfo(
        id = "naver-id",
        email = "test@naver.com",
        mobile = mobile
    )

    "mobile의 하이픈이 제거되어 정규화된다" {
        naverUserInfo("010-1234-5678").getNormalizedMobile() shouldBe "01012345678"
    }

    "mobile이 null이면 null을 반환한다" {
        naverUserInfo(null).getNormalizedMobile() shouldBe null
    }

    "mobile이 빈 문자열이면 null을 반환한다" {
        naverUserInfo("").getNormalizedMobile() shouldBe null
    }

    "국가번호가 포함된 mobile도 숫자만 남는다" {
        naverUserInfo("+82 10-1234-5678").getNormalizedMobile() shouldBe "821012345678"
    }
})
