package com.wq.auth.api.external.oauth

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.external.oauth.dto.NaverUserInfoResponse
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
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.HttpServerErrorException
import org.springframework.web.client.RestClient
import tools.jackson.databind.json.JsonMapper

/**
 * Naver OAuth2 클라이언트
 *
 * Naver OAuth2 API와 통신하여 인가 코드를 액세스 토큰으로 교환하고,
 * 액세스 토큰을 사용하여 사용자 정보를 조회합니다.
 */
@Component
class NaverOAuthClient(
    private val naverOAuthProperties: NaverOAuthProperties,
    private val jsonMapper: JsonMapper,
    private val redirectUriResolver: OAuthRedirectUriResolver,
    private val restClient: RestClient,
) : OAuthClient {
    private val log = KotlinLogging.logger {}

    /**
     * 인가 코드를 사용하여 액세스 토큰을 획득합니다.
     *
     * @param authorizationCode Naver로부터 받은 인가 코드
     * @param state CSRF 방지용 상태 값
     * @param codeVerifier PKCE 검증용 코드 검증자
     * @param requestRedirectUri 요청에 담긴 redirect_uri (있으면 허용 목록 검증 후 사용)
     * @return Naver 액세스 토큰
     * @throws SocialLoginException 토큰 획득 실패 시
     */
    fun getAccessToken(
        authorizationCode: String,
        state: String,
        codeVerifier: String,
        requestRedirectUri: String? = null,
    ): String {
        val redirectUri = redirectUriResolver.resolve(requestRedirectUri, naverOAuthProperties.redirectUri)
        log.info { "Naver 액세스 토큰 요청 시작" }
        log.info { "redirectUri: $redirectUri" }

        val body: MultiValueMap<String, String> = LinkedMultiValueMap<String, String>().apply {
            add("client_id", naverOAuthProperties.clientId)
            add("client_secret", naverOAuthProperties.clientSecret)
            add("code_verifier", codeVerifier)
            add("code", authorizationCode)
            add("grant_type", "authorization_code")
            add("state", state)
            add("redirect_uri", redirectUri)
        }

        try {
            val response = restClient.post()
                .uri(naverOAuthProperties.tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(body)
                .retrieve()
                .toEntity(String::class.java)

            if (response.statusCode == HttpStatus.OK && response.body != null) {
                val tokenResponse = jsonMapper.readTree(response.body!!)
                val accessToken = tokenResponse.get("access_token")?.asString()

                if (accessToken != null) {
                    log.info { "Naver 액세스 토큰 획득 성공" }
                    return accessToken
                } else {
                    log.error { "Naver 액세스 토큰이 응답에 없습니다: ${response.body}" }
                    throw SocialLoginException(SocialLoginExceptionCode.NAVER_TOKEN_REQUEST_FAILED)
                }
            } else {
                log.error { "Naver 토큰 요청 실패: ${response.statusCode}" }
                throw SocialLoginException(SocialLoginExceptionCode.NAVER_TOKEN_REQUEST_FAILED)
            }

        } catch (e: HttpClientErrorException) {
            log.error(e) { "Naver 토큰 요청 클라이언트 오류: ${e.statusCode} - ${e.responseBodyAsString}" }
            throw SocialLoginException(SocialLoginExceptionCode.NAVER_INVALID_AUTHORIZATION_CODE, e)
        } catch (e: HttpServerErrorException) {
            log.error(e) { "Naver 서버 오류: ${e.statusCode}" }
            throw SocialLoginException(SocialLoginExceptionCode.NAVER_SERVER_ERROR, e)
        } catch (e: SocialLoginException) {
            throw e // 이미 SocialLoginException인 경우 그대로 전파
        } catch (e: Exception) {
            log.error(e) { "Naver 토큰 요청 중 예상치 못한 오류 발생" }
            throw SocialLoginException(SocialLoginExceptionCode.NAVER_TOKEN_REQUEST_FAILED, e)
        }
    }

    /**
     * 액세스 토큰을 사용하여 Naver 사용자 정보를 조회합니다.
     *
     * @param accessToken Naver 액세스 토큰
     * @return Naver 사용자 정보
     * @throws SocialLoginException 사용자 정보 조회 실패 시
     */
    fun getUserInfo(accessToken: String): NaverUserInfoResponse {
        log.info { "Naver 사용자 정보 조회 시작" }

        try {
            val response = restClient.get()
                .uri(naverOAuthProperties.userInfoUri)
                .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .toEntity(String::class.java)

            if (response.statusCode == HttpStatus.OK && response.body != null) {
                val userInfo = jsonMapper.readValue(response.body!!, NaverUserInfoResponse::class.java)
                log.info { "Naver 사용자 정보 조회 성공: ${userInfo.response.email ?: "이메일 없음"}" }
                return userInfo
            } else {
                log.error { "Naver 사용자 정보 조회 실패: ${response.statusCode}" }
                throw SocialLoginException(SocialLoginExceptionCode.NAVER_USER_INFO_REQUEST_FAILED)
            }

        } catch (e: HttpClientErrorException) {
            log.error(e) { "Naver 사용자 정보 조회 클라이언트 오류: ${e.statusCode}" }
            throw SocialLoginException(SocialLoginExceptionCode.NAVER_INVALID_ACCESS_TOKEN, e)
        } catch (e: HttpServerErrorException) {
            log.error(e) { "Naver 서버 오류: ${e.statusCode}" }
            throw SocialLoginException(SocialLoginExceptionCode.NAVER_SERVER_ERROR, e)
        } catch (e: SocialLoginException) {
            throw e // 이미 SocialLoginException인 경우 그대로 전파
        } catch (e: Exception) {
            log.error(e) { "Naver 사용자 정보 조회 중 예상치 못한 오류 발생" }
            throw SocialLoginException(SocialLoginExceptionCode.NAVER_USER_INFO_REQUEST_FAILED, e)
        }
    }

    /**
     * OAuthClient 인터페이스 구현: 인가 코드를 사용하여 도메인 사용자 정보를 조회합니다.
     *
     * @param authCode Naver로부터 받은 인가 코드
     * @param state CSRF 방지용 상태 값
     * @param codeVerifier PKCE 검증용 코드 검증자
     * @return 도메인 사용자 정보
     */
    override fun getUserFromAuthCode(req: OAuthAuthCodeRequest): OAuthUser {
        log.info { "Naver AuthCode 요청 시작" }
        val accessToken = getAccessToken(req.authCode, req.state!!, req.codeVerifier, req.redirectUri)
        val naverUserInfo = getUserInfo(accessToken)

        return OAuthUser(
            providerId = naverUserInfo.response.getProviderId(),
            email = naverUserInfo.response.email!!,
            verifiedEmail = naverUserInfo.response.email != null,
            name = naverUserInfo.response.name,
            givenName = naverUserInfo.response.nickname, // 네이버는 givenName이 없으므로 nickname 사용
            providerType = ProviderType.NAVER
        )
    }

    /**
     * 인가 코드를 사용하여 사용자 정보를 직접 조회합니다. (기존 호환성 유지용)
     *
     * @param authorizationCode Naver로부터 받은 인가 코드
     * @param state CSRF 방지용 상태 값
     * @param codeVerifier PKCE 검증용 코드 검증자
     * @return Naver 사용자 정보
     */
    fun getUserInfoFromAuthCode(
        authorizationCode: String,
        state: String,
        codeVerifier: String,
    ): NaverUserInfoResponse {
        val accessToken = getAccessToken(authorizationCode, state, codeVerifier, null)
        return getUserInfo(accessToken)
    }
}