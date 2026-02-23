package com.wq.auth.api.external.oauth

import com.fasterxml.jackson.databind.ObjectMapper
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.external.oauth.dto.GoogleUserInfoResponse
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
import org.springframework.web.client.RestTemplate
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.HttpServerErrorException

/**
 * Google OAuth2 클라이언트
 * 
 * Google OAuth2 API와 통신하여 인가 코드를 액세스 토큰으로 교환하고,
 * 액세스 토큰을 사용하여 사용자 정보를 조회합니다.
 */
@Component
class GoogleOAuthClient(
    private val googleOAuthProperties: GoogleOAuthProperties,
    private val objectMapper: ObjectMapper,
    private val redirectUriResolver: OAuthRedirectUriResolver,
) : OAuthClient {
    private val log = KotlinLogging.logger {}
    private val restTemplate = RestTemplate()

    /**
     * 인가 코드를 사용하여 액세스 토큰을 획득합니다.
     *
     * @param authorizationCode Google로부터 받은 인가 코드
     * @param codeVerifier PKCE 검증용 코드 검증자
     * @param requestRedirectUri 요청에 담긴 redirect_uri (있으면 허용 목록 검증 후 사용)
     * @return Google 액세스 토큰
     * @throws SocialLoginException 토큰 획득 실패 시
     */
    fun getAccessToken(
        authorizationCode: String,
        codeVerifier: String,
        requestRedirectUri: String? = null,
    ): String {
        val redirectUri = redirectUriResolver.resolve(requestRedirectUri, googleOAuthProperties.redirectUri)
        log.info { "Google 액세스 토큰 요청 시작" }
        log.info { "redirectUri: $redirectUri" }

        val headers = HttpHeaders().apply {
            contentType = MediaType.APPLICATION_FORM_URLENCODED
        }

        val body: MultiValueMap<String, String> = LinkedMultiValueMap<String, String>().apply {
            add("client_id", googleOAuthProperties.clientId)
            add("client_secret", googleOAuthProperties.clientSecret)
            add("code", authorizationCode)
            add("grant_type", "authorization_code")
            add("code_verifier", codeVerifier)
            add("redirect_uri", redirectUri)
        }
        
        val request = HttpEntity(body, headers)
        
        try {
            val response = restTemplate.postForEntity(
                googleOAuthProperties.tokenUri,
                request,
                String::class.java
            )
            
            if (response.statusCode == HttpStatus.OK && response.body != null) {
                val tokenResponse = objectMapper.readTree(response.body!!)
                val accessToken = tokenResponse.get("access_token")?.asText()
                
                if (accessToken != null) {
                    log.info { "Google 액세스 토큰 획득 성공" }
                    return accessToken
                } else {
                    log.error { "Google 액세스 토큰이 응답에 없습니다: ${response.body}" }
                    throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_TOKEN_REQUEST_FAILED)
                }
            } else {
                log.error { "Google 토큰 요청 실패: ${response.statusCode}" }
                throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_TOKEN_REQUEST_FAILED)
            }
            
        } catch (e: HttpClientErrorException) {
            log.error(e) { "Google 토큰 요청 클라이언트 오류: ${e.statusCode} - ${e.responseBodyAsString}" }
            throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_INVALID_AUTHORIZATION_CODE, e)
        } catch (e: HttpServerErrorException) {
            log.error(e) { "Google 서버 오류: ${e.statusCode}" }
            throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_SERVER_ERROR, e)
        } catch (e: SocialLoginException) {
            throw e // 이미 SocialLoginException인 경우 그대로 전파
        } catch (e: Exception) {
            log.error(e) { "Google 토큰 요청 중 예상치 못한 오류 발생" }
            throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_TOKEN_REQUEST_FAILED, e)
        }
    }

    /**
     * 액세스 토큰을 사용하여 Google 사용자 정보를 조회합니다.
     * 
     * @param accessToken Google 액세스 토큰
     * @return Google 사용자 정보
     * @throws SocialLoginException 사용자 정보 조회 실패 시
     */
    fun getUserInfo(accessToken: String): GoogleUserInfoResponse {
        log.info { "Google 사용자 정보 조회 시작" }
        
        val headers = HttpHeaders().apply {
            set("Authorization", "Bearer $accessToken")
            contentType = MediaType.APPLICATION_JSON
        }
        
        val request = HttpEntity<String>(headers)
        
        try {
            val response = restTemplate.exchange(
                googleOAuthProperties.userInfoUri,
                HttpMethod.GET,
                request,
                String::class.java
            )
            
            if (response.statusCode == HttpStatus.OK && response.body != null) {
                val userInfo = objectMapper.readValue(response.body!!, GoogleUserInfoResponse::class.java)
                log.info { "Google 사용자 정보 조회 성공: ${userInfo.email}" }
                return userInfo
            } else {
                log.error { "Google 사용자 정보 조회 실패: ${response.statusCode}" }
                throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_USER_INFO_REQUEST_FAILED)
            }
            
        } catch (e: HttpClientErrorException) {
            log.error(e) { "Google 사용자 정보 조회 클라이언트 오류: ${e.statusCode}" }
            throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_INVALID_ACCESS_TOKEN, e)
        } catch (e: HttpServerErrorException) {
            log.error(e) { "Google 서버 오류: ${e.statusCode}" }
            throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_SERVER_ERROR, e)
        } catch (e: SocialLoginException) {
            throw e // 이미 SocialLoginException인 경우 그대로 전파
        } catch (e: Exception) {
            log.error(e) { "Google 사용자 정보 조회 중 예상치 못한 오류 발생" }
            throw SocialLoginException(SocialLoginExceptionCode.GOOGLE_USER_INFO_REQUEST_FAILED, e)
        }
    }

    /**
     * OAuthClient 인터페이스 구현: 인가 코드를 사용하여 도메인 사용자 정보를 조회합니다.
     * 
     * @param authCode Google로부터 받은 인가 코드
     * @param codeVerifier PKCE 검증용 코드 검증자
     * @return 도메인 사용자 정보
     */
    override fun getUserFromAuthCode(req: OAuthAuthCodeRequest): OAuthUser {
        val accessToken = getAccessToken(req.authCode, req.codeVerifier, req.redirectUri)
        val googleUserInfo = getUserInfo(accessToken)
        
        return OAuthUser(
            providerId = googleUserInfo.getProviderId(),
            email = googleUserInfo.email,
            verifiedEmail = googleUserInfo.verifiedEmail,
            name = googleUserInfo.name,
            givenName = googleUserInfo.givenName,
            providerType = ProviderType.GOOGLE
        )
    }

    /**
     * 인가 코드를 사용하여 사용자 정보를 직접 조회합니다. (기존 호환성 유지용)
     * 
     * @param authorizationCode Google로부터 받은 인가 코드
     * @param codeVerifier PKCE 검증용 코드 검증자
     * @return Google 사용자 정보
     */
    fun getUserInfoFromAuthCode(authorizationCode: String, codeVerifier: String): GoogleUserInfoResponse {
        val accessToken = getAccessToken(authorizationCode, codeVerifier, null)
        return getUserInfo(accessToken)
    }
}
