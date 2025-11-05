package com.back.global.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val customAuthenticationFilter: CustomAuthenticationFilter,
    private val customOAuth2LoginSuccessHandler: CustomOAuth2LoginSuccessHandler,
    private val customOAuth2AuthorizationRequestResolver: CustomOAuth2AuthorizationRequestResolver
) {

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {

        http {
            authorizeHttpRequests {
                authorize("/favicon.ico", permitAll)
                authorize("/h2-console/**", permitAll)
                authorize(HttpMethod.GET, "/api/*/posts", permitAll)
                authorize(HttpMethod.GET, "/api/*/posts/{id:\\d+}", permitAll)
                authorize(HttpMethod.GET, "/api/*/posts/{postId:\\d+}/comments", permitAll)
                authorize(HttpMethod.GET, "/api/*/posts/{postId:\\d+}/comments/{commentId:\\d+}", permitAll)
                authorize(HttpMethod.POST, "/api/v1/members/login", permitAll)
                authorize(HttpMethod.POST, "/api/v1/members/join", permitAll)
                authorize(HttpMethod.DELETE, "/api/v1/members/logout", permitAll)
                authorize("/api/*/adm/**", hasRole("ADMIN"))
                authorize("/api/*/**", authenticated)
                authorize(anyRequest, permitAll)
            }

            csrf { disable() }

            headers {
                frameOptions { sameOrigin = true }
            }

            addFilterBefore<UsernamePasswordAuthenticationFilter>(customAuthenticationFilter)
            sessionManagement {
                sessionCreationPolicy = SessionCreationPolicy.STATELESS
            }

            oauth2Login {
                authenticationSuccessHandler = customOAuth2LoginSuccessHandler
                authorizationEndpoint {
                    authorizationRequestResolver = customOAuth2AuthorizationRequestResolver
                }
            }

            exceptionHandling {
                authenticationEntryPoint = AuthenticationEntryPoint { _, response, _ ->
                    response.contentType =
                        "application/json; charset=UTF-8"
                    response.status = 401
                    response.writer.write(
                        """
                            {
                                "resultCode": "401-1",
                                "msg": "로그인 후 이용해주세요."
                            }
                            """.trimIndent()
                    )
                }

                accessDeniedHandler = AccessDeniedHandler { _, response, _ ->
                    response.contentType =
                        "application/json; charset=UTF-8"
                    response.status = 403
                    response.writer.write(
                        """
                            {
                                "resultCode": "403-1",
                                "msg": "권한이 없습니다."
                            }
                        """.trimIndent()
                    )
                }
            }
        }

        return http.build()
    }

    @Bean
    fun corsConfigurationSource(): UrlBasedCorsConfigurationSource {
        val configuration = CorsConfiguration().apply {
            allowedOrigins =
                listOf("https://cdpn.io", "http://localhost:3000")
            allowedMethods =
                listOf("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
            allowedHeaders = listOf("*")
            allowCredentials = true
        }

        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/api/**", configuration)
        }
    }
}