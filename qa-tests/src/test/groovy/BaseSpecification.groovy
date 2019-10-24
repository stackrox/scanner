import com.jayway.restassured.RestAssured
import org.junit.Rule
import org.junit.rules.Timeout
import spock.lang.Specification

import java.util.concurrent.TimeUnit

class BaseSpecification extends Specification {

    @Rule
    Timeout globalTimeout = new Timeout(500000, TimeUnit.MILLISECONDS)

    def setupSpec() {
        RestAssured.useRelaxedHTTPSValidation()
    }
}
