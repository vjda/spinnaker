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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.MockitoAnnotations.openMocks;

import com.netflix.spinnaker.kork.secrets.EncryptedSecret;
import com.netflix.spinnaker.kork.secrets.InvalidSecretFormatException;
import com.netflix.spinnaker.kork.secrets.SecretException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Spy;

public class KubernetesSecretEngineTest {

  @Spy private KubernetesSecretEngine kubernetesSecretEngine = new KubernetesSecretEngine();

  private final byte[] simpleSecretValue = "my-database-password".getBytes();
  private final byte[] jsonSecretValue =
      "{\"username\":\"admin\",\"password\":\"secret123\"}".getBytes();
  private final byte[] fileSecretValue = "-----BEGIN CERTIFICATE-----\nMIIC...".getBytes();

  @BeforeEach
  public void setup() {
    openMocks(this);
  }

  @Test
  public void testIdentifier() {
    assertEquals("k8s", kubernetesSecretEngine.identifier());
  }

  @Test
  public void decryptSimpleString() {
    EncryptedSecret secret = EncryptedSecret.parse("encrypted:k8s!n:my-secret!k:password");
    doReturn(simpleSecretValue)
        .when(kubernetesSecretEngine)
        .getSecretData(eq("my-secret"), eq("password"));

    assertArrayEquals(simpleSecretValue, kubernetesSecretEngine.decrypt(secret));
  }

  @Test
  public void decryptStringWithJsonProperty() {
    EncryptedSecret secret =
        EncryptedSecret.parse("encrypted:k8s!n:my-secret!k:credentials!p:password");
    doReturn(jsonSecretValue)
        .when(kubernetesSecretEngine)
        .getSecretData(eq("my-secret"), eq("credentials"));

    byte[] result = kubernetesSecretEngine.decrypt(secret);
    assertEquals("secret123", new String(result));
  }

  @Test
  public void decryptFile() {
    EncryptedSecret secret = EncryptedSecret.parse("encryptedFile:k8s!n:my-secret!k:cert");
    doReturn(fileSecretValue)
        .when(kubernetesSecretEngine)
        .getSecretData(eq("my-secret"), eq("cert"));

    assertArrayEquals(fileSecretValue, kubernetesSecretEngine.decrypt(secret));
  }

  @Test
  public void decryptFileWithPropertyShouldFail() {
    EncryptedSecret secret =
        EncryptedSecret.parse("encryptedFile:k8s!n:my-secret!k:cert!p:someProperty");

    InvalidSecretFormatException exception =
        assertThrows(
            InvalidSecretFormatException.class, () -> kubernetesSecretEngine.validate(secret));
    assertEquals("Encrypted file should not specify property parameter", exception.getMessage());
  }

  @Test
  public void validateMissingSecretName() {
    EncryptedSecret secret = EncryptedSecret.parse("encrypted:k8s!k:password");

    InvalidSecretFormatException exception =
        assertThrows(
            InvalidSecretFormatException.class, () -> kubernetesSecretEngine.validate(secret));
    assertEquals("Secret name parameter is missing (n=...)", exception.getMessage());
  }

  @Test
  public void validateMissingSecretKey() {
    EncryptedSecret secret = EncryptedSecret.parse("encrypted:k8s!n:my-secret");

    InvalidSecretFormatException exception =
        assertThrows(
            InvalidSecretFormatException.class, () -> kubernetesSecretEngine.validate(secret));
    assertEquals("Secret key parameter is missing (k=...)", exception.getMessage());
  }

  @Test
  public void decryptWithMissingProperty() {
    EncryptedSecret secret =
        EncryptedSecret.parse("encrypted:k8s!n:my-secret!k:credentials!p:nonexistent");
    doReturn(jsonSecretValue)
        .when(kubernetesSecretEngine)
        .getSecretData(eq("my-secret"), eq("credentials"));

    SecretException exception =
        assertThrows(SecretException.class, () -> kubernetesSecretEngine.decrypt(secret));
    assertEquals(
        "Property 'nonexistent' not found in secret 'my-secret' key 'credentials'",
        exception.getMessage());
  }

  @Test
  public void decryptWithInvalidJson() {
    EncryptedSecret secret =
        EncryptedSecret.parse("encrypted:k8s!n:my-secret!k:credentials!p:password");
    byte[] invalidJson = "not-valid-json".getBytes();
    doReturn(invalidJson)
        .when(kubernetesSecretEngine)
        .getSecretData(eq("my-secret"), eq("credentials"));

    SecretException exception =
        assertThrows(SecretException.class, () -> kubernetesSecretEngine.decrypt(secret));
    assertTrue(
        exception
            .getMessage()
            .startsWith("Failed to parse secret 'my-secret' key 'credentials' as JSON"));
  }

  @Test
  public void cacheClearsSuccessfully() {
    kubernetesSecretEngine.clearCache();
    // No exception should be thrown
  }
}
