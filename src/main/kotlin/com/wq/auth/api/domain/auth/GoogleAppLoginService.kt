package com.wq.auth.api.domain.auth

import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.gson.GsonFactory
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.response.SocialLoginResult
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.api.domain.oauth.error.SocialLoginException
import com.wq.auth.api.domain.oauth.error.SocialLoginExceptionCode
import com.wq.auth.api.external.oauth.GoogleOAuthProperties
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Service

/**
 * 안드로이드 앱 전용 Google ID Token 로그인 서비스
 *
 * 앱에서 Google Credential Manager로 발급받은 ID Token을 검증하고,
 * 자체 JWT(AT/RT)를 발급합니다.
 */
@Service
class GoogleAppLoginService(
    private val googleOAuthProperties: GoogleOAuthProperties,
    private val socialLoginMemberProcessor: SocialLoginMemberProcessor,
) {
    private val log = KotlinLogging.logger {}

    fun login(idTokenString: String): SocialLoginResult {
        log.info { "Google 앱 로그인 처리 시작" }

        val verifier = GoogleIdTokenVerifier.Builder(NetHttpTransport(), GsonFactory())
            .setAudience(listOf(googleOAuthProperties.clientId))
            .build()

        val idToken = verifier.verify(idTokenString)
            ?: throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_INVALID_ID_TOKEN)

        val payload = idToken.payload
        val oauthUser = OAuthUser(
            providerId = payload.subject,
            email = payload.email,
            verifiedEmail = payload["email_verified"] as? Boolean ?: false,
            name = payload["name"] as? String,
            givenName = payload["given_name"] as? String,
            providerType = ProviderType.GOOGLE,
        )

        log.info { "Google ID Token 검증 완료: ${oauthUser.email}" }

        return socialLoginMemberProcessor.processMemberAndIssueTokens(oauthUser, ProviderType.GOOGLE)
    }
}
