package com.wq.auth.integration.security

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Spring Security 배선(permitAll vs authenticated)만 확인하기 위한 테스트 전용 컨트롤러.
 *
 * src/test 에 있으므로 프로덕션 배포 아티팩트에 포함되지 않는다.
 * 삭제된 TestSecurityController 와 결정적으로 다른 점은 **토큰을 발급하지 않는다**는 것이다 —
 * 그 컨트롤러는 인증 없이 임의 opaqueId 의 유효 서명 AT 를 내주고 있었다.
 */
@RestController
class _SecurityProbeController {

    /** SecurityConfig 의 anyRequest().authenticated() 에 걸린다. 유효 토큰이 있어야 200. */
    @GetMapping("/api/test-probe/authenticated")
    fun authenticatedProbe(): Map<String, String> = mapOf("ok" to "true")
}
