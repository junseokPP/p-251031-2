package com.back.global.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class CustomOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest req = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
        ).resolve(request);

        return customizeState(req, request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest req =  new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
        ).resolve(request);

        return customizeState(req, request);
    }

    private OAuth2AuthorizationRequest customizeState(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest req) {

        if(authorizationRequest == null) {
            return null;
        }

        String redirectUrl = req.getParameter("redirectUrl");

        if(redirectUrl == null) {
            redirectUrl = "/";
        }

        String originState = authorizationRequest.getState();
        String newState = originState + "#" + redirectUrl;

        String encodedNewState = Base64.getUrlEncoder().encodeToString(newState.getBytes(StandardCharsets.UTF_8));

        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .state(encodedNewState)
                .build();
    }
}
