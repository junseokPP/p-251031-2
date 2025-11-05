package com.back.global.security

import com.back.domain.member.member.entity.Member
import com.back.domain.member.member.service.MemberService
import com.back.global.rq.Rq
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Component
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.*

@Component
class CustomOAuth2LoginSuccessHandler(
    private val memberService: MemberService,
    private val rq: Rq
) : AuthenticationSuccessHandler {

    @Throws(IOException::class, ServletException::class)
    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val member: Member = rq.actor
        val accessToken = memberService.genAccessToken(member)
        val apiKey = member.apiKey

        rq.setCookie("accessToken", accessToken)
        rq.setCookie("apiKey", apiKey)

        val state = request.getParameter("state").orEmpty()
        var redirectUrl = "/"

        if (state.isNotBlank()) {
            runCatching {
                val decodedState = Base64.getUrlDecoder()
                    .decode(state)
                    .toString(StandardCharsets.UTF_8)

                decodedState.split("#", limit = 2)
                    .getOrNull(1)
                    ?.takeIf { it.isNotBlank() }
                    ?.let { redirectUrl = it }
            }
        }

        rq.sendRedirect(redirectUrl)
    }
}
