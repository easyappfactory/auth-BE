package com.wq.auth.api.external.oauth

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.external.oauth.dto.KakaoUserInfoResponse
import com.wq.auth.api.domain.auth.request.OAuthAuthCodeRequest
import com.wq.auth.api.domain.oauth.OAuthClient
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.api.domain.oauth.error.SocialLoginException
import com.wq.auth.api.domain.oauth.error.SocialLoginExceptionCode
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.http.*
import org.springframework.stereotype.Component
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.RestClient
import tools.jackson.databind.json.JsonMapper

@Component
class KakaoOAuthClient(
    private val kakaoOAuthProperties: KakaoOAuthProperties,
    private val jsonMapper: JsonMapper,
    private val redirectUriResolver: OAuthRedirectUriResolver,
    private val restClient: RestClient,
) : OAuthClient {
    private val log = KotlinLogging.logger {}

    fun getTokenResponse(
        authorizationCode: String,
        codeVerifier: String,
        requestRedirectUri: String? = null,
    ): Map<String, String> {
        val redirectUri = redirectUriResolver.resolve(requestRedirectUri, kakaoOAuthProperties.redirectUri)
        log.info { "카카오 토큰 요청 시작" }

        val body: MultiValueMap<String, String> = LinkedMultiValueMap<String, String>().apply {
            add("grant_type", "authorization_code")
            add("client_id", kakaoOAuthProperties.clientId)
            if (!kakaoOAuthProperties.clientSecret.isNullOrBlank()) {
                add("client_secret", kakaoOAuthProperties.clientSecret)
            }
            add("redirect_uri", redirectUri)
            add("code", authorizationCode)
            if (codeVerifier.isNotBlank()) {
                add("code_verifier", codeVerifier)
            }
        }

        try {
            val response = restClient.post()
                .uri(kakaoOAuthProperties.tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(body)
                .retrieve()
                .toEntity(String::class.java)
            
            if (response.statusCode == HttpStatus.OK && response.body != null) {
                val tokenResponse = jsonMapper.readTree(response.body!!)
                val accessToken = tokenResponse.get("access_token")?.asString()
                val idToken = tokenResponse.get("id_token")?.asString()
                
                if (accessToken != null) {
                    log.info { "카카오 토큰 획득 성공" }
                    val result = mutableMapOf("access_token" to accessToken)
                    idToken?.let { result["id_token"] = it }
                    return result
                } else {
                    log.error { "카카오 액세스 토큰이 응답에 없습니다" }
                    throw SocialLoginException(SocialLoginExceptionCode.KAKAO_TOKEN_REQUEST_FAILED)
                }
            } else {
                log.error { "카카오 토큰 요청 실패: ${response.statusCode}" }
                throw SocialLoginException(SocialLoginExceptionCode.KAKAO_TOKEN_REQUEST_FAILED)
            }
        } catch (e: Exception) {
            log.error(e) { "카카오 토큰 요청 중 오류 발생" }
            throw SocialLoginException(SocialLoginExceptionCode.KAKAO_TOKEN_REQUEST_FAILED, e)
        }
    }

    override fun getUserFromAuthCode(req: OAuthAuthCodeRequest): OAuthUser {
        val tokenResponse = getTokenResponse(req.authCode, req.codeVerifier, req.redirectUri)
        val accessToken = tokenResponse["access_token"]!!
        val idToken = tokenResponse["id_token"]

        if (idToken != null) {
            try {
                val chunks = idToken.split(".")
                if (chunks.size >= 2) {
                    val payload = String(java.util.Base64.getUrlDecoder().decode(chunks[1]))
                    val jsonNode = jsonMapper.readTree(payload)
                    
                    return OAuthUser(
                        providerId = jsonNode.get("sub").asString(),
                        email = jsonNode.get("email")?.asString() ?: "",
                        verifiedEmail = jsonNode.get("email_needs_agreement")?.asBoolean()?.not() ?: true,
                        name = jsonNode.get("nickname")?.asString() ?: "카카오사용자",
                        givenName = jsonNode.get("nickname")?.asString(),
                        providerType = ProviderType.KAKAO
                    )
                }
            } catch (e: Exception) {
                log.warn { "id_token 파싱 실패: ${e.message}" }
            }
        }

        val kakaoUserInfo = getUserInfo(accessToken)
        
        return OAuthUser(
            providerId = kakaoUserInfo.getProviderId(),
            email = kakaoUserInfo.getEmail(),
            verifiedEmail = kakaoUserInfo.isEmailVerified(),
            name = kakaoUserInfo.getNickname(),
            givenName = kakaoUserInfo.getNickname(),
            providerType = ProviderType.KAKAO
        )
    }

    fun getUserInfo(accessToken: String): KakaoUserInfoResponse {
        try {
            val response = restClient.get()
                .uri(kakaoOAuthProperties.userInfoUri)
                .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .toEntity(String::class.java)

            if (response.statusCode == HttpStatus.OK && response.body != null) {
                return jsonMapper.readValue(response.body!!, KakaoUserInfoResponse::class.java)
            } else {
                throw SocialLoginException(SocialLoginExceptionCode.KAKAO_USER_INFO_REQUEST_FAILED)
            }
        } catch (e: Exception) {
            log.error(e) { "카카오 사용자 정보 조회 중 오류 발생" }
            throw SocialLoginException(SocialLoginExceptionCode.KAKAO_USER_INFO_REQUEST_FAILED, e)
        }
    }

    fun getUserInfoFromAuthCode(authorizationCode: String, codeVerifier: String): KakaoUserInfoResponse {
        val tokenResponse = getTokenResponse(authorizationCode, codeVerifier, null)
        val accessToken = tokenResponse["access_token"]!!
        return getUserInfo(accessToken)
    }
}
