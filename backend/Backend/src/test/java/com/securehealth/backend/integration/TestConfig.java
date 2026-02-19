package com.securehealth.backend.integration;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration;
import org.springframework.context.annotation.Configuration;

/**
 * Test configuration to disable Redis for integration tests.
 * This prevents Redis connection errors in CI environments.
 */
@Configuration
@EnableAutoConfiguration(exclude = {
    RedisAutoConfiguration.class,
    RedisRepositoriesAutoConfiguration.class
})
public class TestConfig {
    // This configuration class disables Redis autoconfiguration for tests
}
