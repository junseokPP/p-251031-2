package com.back.global.security

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.stereotype.Component
import java.nio.charset.StandardCharsets
import java.util.*

@Component
class CustomOAuth2AuthorizationRequestResolver(
    private val clientRegistrationRepository: ClientRegistrationRepository
) : OAuth2AuthorizationRequestResolver {

    private val delegate = DefaultOAuth2AuthorizationRequestResolver(
        clientRegistrationRepository,
        OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
    )

    override fun resolve(request: HttpServletRequest): OAuth2AuthorizationRequest? {
        val req = delegate.resolve(request)
        return customizeState(req, request)
    }

    override fun resolve(request: HttpServletRequest, clientRegistrationId: String): OAuth2AuthorizationRequest? {
        val req = delegate.resolve(request, clientRegistrationId)
        return customizeState(req, request)
    }

    private fun customizeState(
        authorizationRequest: OAuth2AuthorizationRequest?,
        req: HttpServletRequest
    ): OAuth2AuthorizationRequest? {
        authorizationRequest ?: return null

        val redirectUrl = req.getParameter("redirectUrl") ?: "/"

        val originState = authorizationRequest.state ?: ""
        val newState = "$originState#$redirectUrl"

        val encodedNewState = Base64.getUrlEncoder()
            .encodeToString(newState.toByteArray(StandardCharsets.UTF_8))

        return OAuth2AuthorizationRequest.from(authorizationRequest)
            .state(encodedNewState)
            .build()
    }
}
