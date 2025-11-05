package com.back.global.security

import com.back.domain.member.member.entity.Member
import com.back.domain.member.member.service.MemberService
import com.back.global.exception.ServiceException
import com.back.global.rq.Rq
import com.back.global.rsData.RsData
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class CustomAuthenticationFilter(
    private val memberService: MemberService,
    private val rq: Rq
) : OncePerRequestFilter() {

    @Throws(ServletException::class, java.io.IOException::class)
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        logger.debug("CustomAuthenticationFilter called")

        try {
            authenticate(request, response, filterChain)
        } catch (e: ServiceException) {
            val rsData: RsData<*> = e.rsData
            response.contentType = "application/json"
            response.status = rsData.statusCode
            response.writer.write(
                """
                {
                  "resultCode": "${rsData.resultCode}",
                  "msg": "${rsData.msg}"
                }
                """.trimIndent()
            )
        } catch (e: Exception) {
            throw e
        }
    }

    @Throws(ServletException::class, java.io.IOException::class)
    private fun authenticate(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val uri = request.requestURI
        if (!uri.startsWith("/api/")) {
            filterChain.doFilter(request, response)
            return
        }

        if (uri in listOf("/api/v1/members/join", "/api/v1/members/login")) {
            filterChain.doFilter(request, response)
            return
        }

        val headerAuthorization = rq.getHeader("Authorization", "")
        val (apiKey, accessToken) = if (headerAuthorization.isNotBlank()) {
            if (!headerAuthorization.startsWith("Bearer ")) {
                throw ServiceException("401-2", "Authorization 헤더가 Bearer 형식이 아닙니다.")
            }
            val bits = headerAuthorization.split(" ", limit = 3)
            val key = bits.getOrNull(1).orEmpty()
            val token = bits.getOrNull(2).orEmpty()
            key to token
        } else {
            rq.getCookieValue("apiKey", "") to rq.getCookieValue("accessToken", "")
        }

        val isApiKeyExists = apiKey.isNotBlank()
        val isAccessTokenExists = accessToken.isNotBlank()

        if (!isApiKeyExists && !isAccessTokenExists) {
            filterChain.doFilter(request, response)
            return
        }

        var member: Member? = null
        var isAccessTokenValid = false

        if (isAccessTokenExists) {
            val payload: Map<String, Any?>? = memberService.payloadOrNull(accessToken)
            if (payload != null) {
                val id = (payload["id"] as? Number)?.toLong()
                val username = payload["username"] as? String
                val nickname = payload["nickname"] as? String

                if (id != null && username != null && nickname != null) {
                    member = Member(id, username, nickname)
                    isAccessTokenValid = true
                }
            }
        }

        if (member == null) {
            member = memberService
                .findByApiKey(apiKey)
                .orElseThrow { ServiceException("401-3", "API 키가 유효하지 않습니다.") }
        }

        // 여기서부터는 member 가 null 일 수 없도록 확정
        val memberNonNull = member!!

        if (isAccessTokenExists && !isAccessTokenValid) {
            val newAccessToken = memberService.genAccessToken(memberNonNull)
            rq.setCookie("accessToken", newAccessToken)
            rq.setHeader("accessToken", newAccessToken)
        }

        val user: UserDetails = SecurityUser(
            id = memberNonNull.id,
            username = memberNonNull.username,
            password = "",
            nickname = memberNonNull.nickname,
            authorities = memberNonNull.authorities
        )

        val authentication = UsernamePasswordAuthenticationToken(
            user,
            user.password,
            user.authorities
        )

        SecurityContextHolder.getContext().authentication = authentication
        filterChain.doFilter(request, response)
    }
}
