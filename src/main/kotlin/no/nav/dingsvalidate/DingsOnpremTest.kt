package no.nav.dingsvalidate

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.DeserializationFeature
import com.nimbusds.jose.util.Resource
import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.authenticate
import io.ktor.auth.principal
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.features.json.JacksonSerializer
import io.ktor.client.features.json.JsonFeature
import io.ktor.client.request.get
import io.ktor.http.ContentType
import io.ktor.http.withCharset
import io.ktor.response.respondText
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.util.KtorExperimentalAPI
import java.net.URL
import kotlinx.coroutines.runBlocking
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.ktor.TokenValidationContextPrincipal
import no.nav.security.token.support.ktor.tokenValidationSupport
import no.nav.security.token.support.test.FileResourceRetriever

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

data class ApplicationStatus(var running: Boolean = true, var initialized: Boolean = false)

@KtorExperimentalAPI
@Suppress("unused")
fun Application.module(enableMock: Boolean = this.environment.config.property("no.nav.security.jwt.mock.enable").getString().toBoolean()) {

    val config = this.environment.config
    val applicationStatus = ApplicationStatus()

    install(Authentication) {
        if (enableMock)
            tokenValidationSupport(config = config, resourceRetriever = mockResourceRetriever)
        else
            tokenValidationSupport(config = config)
    }

    install(Routing) {
        authenticate {
            get("/hello") {
                val principal = call.principal<TokenValidationContextPrincipal>()
                val claims = principal?.context?.anyValidClaims?.orElse(null)
                call.respondText(
                    "<b>Authenticated hello for token with sub='${claims?.subject}' with pid='${claims?.get("pid")}'</b>",
                    ContentType.Text.Html
                )
            }
        }
        selfTest(readySelfTestCheck = { applicationStatus.initialized }, aLiveSelfTestCheck = { applicationStatus.running })
    }
    applicationStatus.initialized = true
}

internal val defaultHttpClient = HttpClient(CIO) {
    install(JsonFeature) {
        serializer = JacksonSerializer {
            configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            setSerializationInclusion(JsonInclude.Include.NON_NULL)
        }
    }
}

class HttpClientResourceRetriever(private val httpClient: HttpClient) : ProxyAwareResourceRetriever() {
    override fun retrieveResource(url: URL?): Resource {
        val content: String = runBlocking {
            httpClient.get<String>(url!!)
        }
        return Resource(content, ContentType.Application.Json.withCharset(Charsets.UTF_8).toString())
    }
}

private val mockResourceRetriever: ProxyAwareResourceRetriever =
    FileResourceRetriever("/metadata.json", "/jwkset.json")
