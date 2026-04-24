package com.devsecops.vulncheckerbackend;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;
import org.springframework.boot.test.context.SpringBootTest;

// @SpringBootTest
class VulncheckerbackendApplicationTests {

	@Test
	@Disabled("Skipped in Jenkins due to missing Postgres DB context")
	void contextLoads() {
	}

}
