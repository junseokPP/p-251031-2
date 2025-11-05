package com.back.global.security

import com.back.domain.member.member.entity.Member
import com.back.domain.member.member.service.MemberService
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class CustomOAuth2UserService(
    private val memberService: MemberService
) : DefaultOAuth2UserService() {

    @Transactional
    @Throws(OAuth2AuthenticationException::class)
    override fun loadUser(userRequest: OAuth2UserRequest): OAuth2User {
        val oAuth2User = super.loadUser(userRequest)

        val oauthUserId = oAuth2User.name
        val providerTypeCode = userRequest.clientRegistration.registrationId.uppercase()

        val attributes: Map<String, Any?> = oAuth2User.attributes
        val attributesProperties = attributes["properties"] as? Map<*, *>

        val userNicknameAttributeName = "nickname"
        val profileImgUrlAttributeName = "profile_image"

        val nickname = attributesProperties?.get(userNicknameAttributeName) as? String ?: ""
        val profileImgUrl = attributesProperties?.get(profileImgUrlAttributeName) as? String ?: ""

        val username = "${providerTypeCode}__$oauthUserId"
        val password = ""

        val member: Member = memberService.modifyOrJoin(username, password, nickname, profileImgUrl)

        return SecurityUser(
            id = member.id,
            username = member.username,
            password = member.password,
            nickname = member.nickname,
            authorities = member.authorities
        )
    }
}
