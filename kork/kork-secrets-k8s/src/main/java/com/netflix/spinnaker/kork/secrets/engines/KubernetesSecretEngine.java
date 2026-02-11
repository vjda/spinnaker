/*
 * Copyright 2026 Mercadona, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.kork.secrets.engines;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.spinnaker.kork.secrets.EncryptedSecret;
import com.netflix.spinnaker.kork.secrets.InvalidSecretFormatException;
import com.netflix.spinnaker.kork.secrets.SecretEngine;
import com.netflix.spinnaker.kork.secrets.SecretException;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Secret;
import io.kubernetes.client.util.Config;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Kubernetes secret engine that retrieves secrets from the Kubernetes cluster where Spinnaker is
 * running.
 *
 * <p>Syntax: encrypted:k8s!n:&lt;secret-name&gt;!k:&lt;key-name&gt;[!p:&lt;property-name&gt;]
 *
 * <p>For files: encryptedFile:k8s!n:&lt;secret-name&gt;!k:&lt;key-name&gt;
 *
 * <p>Examples:
 *
 * <ul>
 *   <li>encrypted:k8s!n:spinnaker-db!k:jdbcurl - Returns the value of key 'jdbcurl' in secret
 *       'spinnaker-db'
 *   <li>encrypted:k8s!n:spinnaker-db!k:credentials!p:password - Parses 'credentials' key as JSON
 *       and returns the 'password' property
 *   <li>encryptedFile:k8s!n:spinnaker-kubeconfig!k:kubeconfig - Returns the 'kubeconfig' key as a
 *       temporary file
 * </ul>
 */
@Component
@Slf4j
public class KubernetesSecretEngine implements SecretEngine {
  private static final String IDENTIFIER = "k8s";
  private static final String NAMESPACE_FILE =
      "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

  private static final String SECRET_NAME =
      KubernetesSecretParameter.SECRET_NAME.getParameterName();
  private static final String SECRET_KEY = KubernetesSecretParameter.SECRET_KEY.getParameterName();
  private static final String SECRET_PROPERTY =
      KubernetesSecretParameter.SECRET_PROPERTY.getParameterName();

  private final AtomicReference<CoreV1Api> kubernetesApi = new AtomicReference<>();
  private final AtomicReference<String> namespace = new AtomicReference<>();
  private final Map<String, CachedSecret> cache = new ConcurrentHashMap<>();
  private static final ObjectMapper objectMapper = new ObjectMapper();

  @Value("${secrets.k8s.namespace:#{null}}")
  private String configuredNamespace;

  @Value("${secrets.k8s.cache-ttl-seconds:0}")
  private long cacheTtlSeconds;

  @Override
  public String identifier() {
    return IDENTIFIER;
  }

  @Override
  public byte[] decrypt(EncryptedSecret encryptedSecret) {
    String secretName = encryptedSecret.getParams().get(SECRET_NAME);
    String secretKey = encryptedSecret.getParams().get(SECRET_KEY);
    String secretProperty = encryptedSecret.getParams().get(SECRET_PROPERTY);

    byte[] secretData = getSecretData(secretName, secretKey);

    if (encryptedSecret.isEncryptedFile()) {
      // For encrypted files, return the raw bytes
      return secretData;
    } else if (secretProperty != null) {
      // Parse as JSON/YAML and extract the property
      return extractPropertyFromJson(secretData, secretProperty, secretName, secretKey);
    } else {
      // Return the raw secret value
      return secretData;
    }
  }

  @Override
  public void validate(EncryptedSecret encryptedSecret) {
    Set<String> paramNames = encryptedSecret.getParams().keySet();

    if (!paramNames.contains(SECRET_NAME)) {
      throw new InvalidSecretFormatException(
          "Secret name parameter is missing (" + SECRET_NAME + "=...)");
    }

    if (!paramNames.contains(SECRET_KEY)) {
      throw new InvalidSecretFormatException(
          "Secret key parameter is missing (" + SECRET_KEY + "=...)");
    }

    if (encryptedSecret.isEncryptedFile() && paramNames.contains(SECRET_PROPERTY)) {
      throw new InvalidSecretFormatException(
          "Encrypted file should not specify property parameter");
    }
  }

  @Override
  public void clearCache() {
    cache.clear();
  }

  /**
   * Retrieves secret data from Kubernetes, using cache if TTL is configured and entry is still
   * valid.
   */
  protected byte[] getSecretData(String secretName, String secretKey) {
    String cacheKey = secretName + ":" + secretKey;

    // Check cache if TTL is enabled
    if (cacheTtlSeconds > 0) {
      CachedSecret cached = cache.get(cacheKey);
      if (cached != null && !cached.isExpired(cacheTtlSeconds)) {
        log.debug(
            "Using cached secret data for secret: {}, key: {} from namespace: {}",
            secretName,
            secretKey,
            getNamespace());
        return cached.getData();
      }
    }

    // Fetch from Kubernetes
    byte[] data = fetchSecretFromKubernetes(secretName, secretKey);

    // Cache the result if TTL is enabled
    if (cacheTtlSeconds > 0) {
      cache.put(cacheKey, new CachedSecret(data));
    }

    return data;
  }

  /**
   * Fetches a secret from the Kubernetes API.
   *
   * @param secretName The name of the Kubernetes secret
   * @param secretKey The key within the secret
   * @return The secret data as bytes (already base64 decoded by the Kubernetes client)
   */
  private byte[] fetchSecretFromKubernetes(String secretName, String secretKey) {
    try {
      CoreV1Api api = getKubernetesApi();
      String ns = getNamespace();

      log.debug("Fetching secret: {} with key: {} from namespace: {}", secretName, secretKey, ns);

      V1Secret secret = api.readNamespacedSecret(secretName, ns, null);

      if (secret.getData() == null) {
        throw new SecretException(
            String.format("Secret '%s' in namespace '%s' has no data section", secretName, ns));
      }

      byte[] data = secret.getData().get(secretKey);
      if (data == null) {
        throw new SecretException(
            String.format(
                "Key '%s' not found in secret '%s' in namespace '%s'", secretKey, secretName, ns));
      }

      return data;
    } catch (ApiException e) {
      throw new SecretException(
          String.format(
              "Failed to fetch secret '%s' with key '%s' from Kubernetes: %s",
              secretName, secretKey, e.getMessage()),
          e);
    }
  }

  /**
   * Extracts a property from JSON-encoded secret data.
   *
   * @param secretData The raw secret data
   * @param property The property name to extract
   * @param secretName The secret name (for error messages)
   * @param secretKey The secret key (for error messages)
   * @return The property value as bytes
   */
  private byte[] extractPropertyFromJson(
      byte[] secretData, String property, String secretName, String secretKey) {
    try {
      String jsonString = new String(secretData, StandardCharsets.UTF_8);
      Map<String, Object> map = objectMapper.readValue(jsonString, Map.class);

      Object value = map.get(property);
      if (value == null) {
        throw new SecretException(
            String.format(
                "Property '%s' not found in secret '%s' key '%s'",
                property, secretName, secretKey));
      }

      if (value instanceof String) {
        return ((String) value).getBytes(StandardCharsets.UTF_8);
      } else {
        // For non-string values, serialize back to JSON
        return objectMapper.writeValueAsString(value).getBytes(StandardCharsets.UTF_8);
      }
    } catch (JsonProcessingException e) {
      throw new SecretException(
          String.format(
              "Failed to parse secret '%s' key '%s' as JSON: %s",
              secretName, secretKey, e.getMessage()),
          e);
    }
  }

  /** Gets or initializes the Kubernetes API client. */
  private CoreV1Api getKubernetesApi() {
    CoreV1Api api = kubernetesApi.get();

    if (api == null) {
      try {
        ApiClient client = Config.defaultClient();
        api = new CoreV1Api(client);
        kubernetesApi.compareAndSet(null, api);
      } catch (IOException e) {
        throw new SecretException(
            "Failed to initialize Kubernetes client. Ensure the application is running in a Kubernetes cluster with proper service account permissions.",
            e);
      }
    }

    return api;
  }

  /**
   * Gets the Kubernetes namespace where secrets should be read from.
   *
   * <p>Priority:
   *
   * <ol>
   *   <li>Configured namespace via secrets.k8s.namespace property
   *   <li>Namespace from service account file
   *       (/var/run/secrets/kubernetes.io/serviceaccount/namespace)
   *   <li>Default to "default" namespace
   * </ol>
   */
  private String getNamespace() {
    String ns = namespace.get();

    if (ns == null) {
      // First check if explicitly configured
      if (configuredNamespace != null && !configuredNamespace.isEmpty()) {
        ns = configuredNamespace;
        log.info("Using configured Kubernetes namespace for secrets: {}", ns);
      } else {
        // Try to read from service account namespace file
        ns = readNamespaceFromFile().orElse("default");
        log.info("Using Kubernetes namespace for secrets: {}", ns);
      }

      namespace.compareAndSet(null, ns);
    }

    return ns;
  }

  /**
   * Reads the namespace from the service account namespace file.
   *
   * @return The namespace if the file exists and is readable, otherwise empty
   */
  private Optional<String> readNamespaceFromFile() {
    try {
      if (Files.exists(Paths.get(NAMESPACE_FILE))) {
        String ns = Files.readString(Paths.get(NAMESPACE_FILE), StandardCharsets.UTF_8).trim();
        if (!ns.isEmpty()) {
          return Optional.of(ns);
        }
      }
    } catch (IOException e) {
      log.warn("Failed to read namespace from {}: {}", NAMESPACE_FILE, e.getMessage());
    }
    return Optional.empty();
  }

  /** Represents a cached secret with timestamp for TTL validation. */
  private static class CachedSecret {
    private final byte[] data;
    private final Instant timestamp;

    CachedSecret(byte[] data) {
      this.data = data;
      this.timestamp = Instant.now();
    }

    byte[] getData() {
      return data;
    }

    boolean isExpired(long ttlSeconds) {
      return Instant.now().isAfter(timestamp.plusSeconds(ttlSeconds));
    }
  }
}
