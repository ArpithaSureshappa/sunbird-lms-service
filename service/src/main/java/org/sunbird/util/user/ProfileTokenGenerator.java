package org.sunbird.util.user;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.sunbird.datasecurity.EncryptionService;
import org.sunbird.datasecurity.impl.ServiceFactory;
import org.sunbird.keys.JsonKey;
import org.sunbird.logging.LoggerUtil;
import org.sunbird.request.RequestContext;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Builds the {@code profileToken} attribute returned by the user read APIs (v1, v2 and v5).
 *
 * <p>The token is the AES encrypted form of a compact JSON document carrying the user's profile
 * context - profile status, civil service details, designation, group, org and roles. Consumers
 * decrypt it back to the JSON using {@link org.sunbird.datasecurity.DecryptionService}, which uses
 * the same {@code sunbird_encryption_key} salt as {@code encEmail} / {@code encPhone}.
 */
public class ProfileTokenGenerator {

  private static final LoggerUtil logger = new LoggerUtil(ProfileTokenGenerator.class);
  private static final ObjectMapper mapper = new ObjectMapper();
  private static final EncryptionService encryptionService =
      ServiceFactory.getEncryptionServiceInstance();

  // Attribute names inside the encrypted payload
  private static final String TOKEN_PROFILE_STATUS = "profilestatus";
  private static final String TOKEN_SERVICE = "service";
  private static final String TOKEN_USER = "user";
  private static final String TOKEN_ROOT_ORG_ID = "rootorgid";

  private ProfileTokenGenerator() {}

  /**
   * Generates the encrypted profile token for the given user read response.
   *
   * @param userProfile the user read response being built, after profileDetails, rootOrg and roles
   *     have been populated
   * @param userId id of the user being read
   * @param context request context, used only for logging
   * @return the encrypted token, or null when it could not be built
   */
  public static String generate(
      Map<String, Object> userProfile, String userId, RequestContext context) {
    try {
      Map<String, Object> profileDetails = asMap(userProfile.get(JsonKey.PROFILE_DETAILS));
      Map<String, Object> personalDetails = asMap(profileDetails.get(JsonKey.PERSONAL_DETAILS));
      Map<String, Object> cadreDetails = asMap(profileDetails.get(JsonKey.CADRE_DETAILS));
      Map<String, Object> professionalDetails =
          firstEntry(profileDetails.get(JsonKey.PROFESSIONAL_DETAILS));
      Map<String, Object> rootOrg = asMap(userProfile.get(JsonKey.ROOT_ORG));

      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put(TOKEN_PROFILE_STATUS, asString(profileDetails.get(JsonKey.PROFILE_STATUS)));
      payload.put(
          TOKEN_SERVICE,
          firstNotBlank(
              personalDetails.get(JsonKey.SERVICE_TYPE), cadreDetails.get(JsonKey.CIVIL_SERVICE_NAME)));
      payload.put(
          JsonKey.BATCH,
          firstNotBlank(personalDetails.get(JsonKey.BATCH), cadreDetails.get(JsonKey.CADRE_BATCH)));
      payload.put(
          JsonKey.CADRE,
          firstNotBlank(personalDetails.get(JsonKey.CADRE), cadreDetails.get(JsonKey.CADRE_NAME)));
      payload.put(JsonKey.DESIGNATION, asString(professionalDetails.get(JsonKey.DESIGNATION)));
      payload.put(
          TOKEN_USER,
          StringUtils.isNotBlank(userId) ? userId : asString(userProfile.get(JsonKey.USER_ID)));
      payload.put(TOKEN_ROOT_ORG_ID, asString(userProfile.get(JsonKey.ROOT_ORG_ID)));
      payload.put(JsonKey.GROUP, asString(professionalDetails.get(JsonKey.GROUP)));
      payload.put(
          JsonKey.MINISTRY_STATE_ID,
          firstNotBlank(
              profileDetails.get(JsonKey.MINISTRY_STATE_ID), rootOrg.get(JsonKey.MINISTRY_STATE_ID)));
      payload.put(
          JsonKey.MINISTRY_STATE_TYPE,
          firstNotBlank(
              profileDetails.get(JsonKey.MINISTRY_STATE_TYPE),
              rootOrg.get(JsonKey.MINISTRY_STATE_TYPE)));
      payload.put(JsonKey.ROLES, roleNames(userProfile.get(JsonKey.ROLES)));

      return encryptionService.encryptData(mapper.writeValueAsString(payload), context);
    } catch (Exception e) {
      // The read response must not fail because the token could not be built
      logger.error(
          context,
          "ProfileTokenGenerator:generate: unable to build profileToken for user " + userId,
          e);
      return null;
    }
  }

  /** Roles are held either as plain names or as role objects, depending on the read version. */
  private static List<String> roleNames(Object roles) {
    if (!(roles instanceof List) || CollectionUtils.isEmpty((List) roles)) {
      return Collections.emptyList();
    }
    return ((List<Object>) roles)
        .stream()
            .map(
                role ->
                    role instanceof Map
                        ? asString(((Map<String, Object>) role).get(JsonKey.ROLE))
                        : asString(role))
            .filter(StringUtils::isNotBlank)
            .collect(Collectors.toList());
  }

  private static Map<String, Object> asMap(Object value) {
    return value instanceof Map ? (Map<String, Object>) value : Collections.emptyMap();
  }

  private static Map<String, Object> firstEntry(Object value) {
    if (value instanceof List && CollectionUtils.isNotEmpty((List) value)) {
      return asMap(((List<Object>) value).get(0));
    }
    return Collections.emptyMap();
  }

  private static String asString(Object value) {
    return null == value ? "" : String.valueOf(value);
  }

  private static String firstNotBlank(Object preferred, Object fallback) {
    String value = asString(preferred);
    return StringUtils.isNotBlank(value) ? value : asString(fallback);
  }
}
