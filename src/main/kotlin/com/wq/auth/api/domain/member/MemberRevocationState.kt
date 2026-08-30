package com.wq.auth.api.domain.member

import java.time.Instant

/**
 * 토큰 폐기 판정에 필요한 최소 상태.
 *
 * **엔티티를 통째로 로딩하지 않는 이유** — 이 조회는 introspect 핫패스에서 돈다.
 * 필요한 것은 두 값뿐이다.
 *
 * **조회 결과가 `null` 이라는 것 자체가 신호다** — 회원 행이 없다는 뜻이고
 * 탈퇴(hard delete)한 계정을 의미한다. 스칼라 값 하나만 뽑으면 "회원 없음"과
 * "폐기 이력 없음"이 둘 다 `null` 로 뭉개져 구분할 수 없다.
 *
 * **인터페이스 프로젝션이 아니라 생성자 표현식(`select new ...`)을 쓴다.**
 * 인터페이스 프로젝션은 별칭과 게터 이름을 매칭하는데, Kotlin 의 `is` 접두사 프로퍼티는
 * `isDeleted()` 게터가 되어 Spring Data 가 프로퍼티명을 `deleted` 로 해석한다.
 * 별칭을 `isDeleted` 로 두면 매칭에 실패해 **조용히 null 이 들어오고**,
 * 그 결과 Kotlin non-null 타입에서 NPE 가 난다(실제로 겪었다).
 * 생성자 표현식은 위치 기반이라 이런 이름 매칭 실패가 원천적으로 없다.
 */
data class MemberRevocationState(
    /** soft delete 여부. 계정 병합으로 흡수된 회원이 여기에 해당한다. */
    val isDeleted: Boolean,

    /** 이 시각 이전(=이하)에 발급된 토큰은 폐기된 것으로 본다. null 이면 폐기 이력 없음. */
    val tokensInvalidBefore: Instant?,
)
