package fr.lacontrevoie.altcha.keycloak.authenticator;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import org.json.JSONObject;

import jakarta.ws.rs.core.MultivaluedMap;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

import org.altcha.altcha.Altcha;
import org.altcha.altcha.Altcha.ChallengeOptions;
import org.altcha.altcha.Altcha.Challenge;

public class RegistrationAltcha implements FormAction, FormActionFactory {
    public static final String ALTCHA_RESPONSE = "altcha-response";
    public static final String ALTCHA_REFERENCE_CATEGORY = "altcha";
    public static final String HMAC_SECRET = "secret";

    public static final String PROVIDER_ID = "registration-altcha-action";

    @Override
    public void close() {

    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "ALTCHA";
    }

    @Override
    public String getReferenceCategory() {
        return ALTCHA_REFERENCE_CATEGORY;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Adds ALTCHA button.  ALTCHA verify that the entity that is registering is a human. It must be configured after you add it.";
    }


    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();

        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(HMAC_SECRET) == null
                ) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }

        // retrieve ALTCHA settings
        String hmacSecret = captchaConfig.getConfig().get(HMAC_SECRET);
        String compact = captchaConfig.getConfig().get("compact");

        // create challenge
        Altcha.ChallengeOptions options = new Altcha.ChallengeOptions();
        options.number = 100L;
        options.hmacKey = hmacSecret;

        // create payload
        try {
            Altcha.Challenge challenge = Altcha.createChallenge(options);
            Altcha.Payload payload = new Altcha.Payload();
            payload.algorithm = challenge.algorithm;
            payload.challenge = challenge.challenge;
            payload.number = options.number;
            payload.salt = challenge.salt;
            payload.signature = challenge.signature;
        
            // add payload data to the form
            JSONObject jsonPayload = new JSONObject();

            jsonPayload.put("algorithm", payload.algorithm);
            jsonPayload.put("challenge", payload.challenge);
            jsonPayload.put("number", payload.number);
            jsonPayload.put("salt", payload.salt);
            jsonPayload.put("signature", payload.signature);

            String encodedPayload = Base64.getEncoder().encodeToString(jsonPayload.toString().getBytes());
            form.setAttribute("altchaPayload", encodedPayload);
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }

        /*form.setAttribute("hcaptchaRequired", true);
        form.setAttribute("hcaptchaCompact", compact);
        form.setAttribute("hcaptchaSiteKey", siteKey);
        form.addScript("https://js.hcaptcha.com/1/api.js?hl=" + userLanguageTag);*/

    }

    @Override
    public void validate(ValidationContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String captcha_resp = formData.getFirst(ALTCHA_RESPONSE);

        if (!Validation.isBlank(captcha_resp)) {
            // retrieve HMAC key
            AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
            String hmacKey = captchaConfig.getConfig().get(HMAC_SECRET);

            try {
                // check if captcha solution is valid
                success = Altcha.verifySolution(captcha_resp, hmacKey, true);
            } catch (Exception e) {
                ServicesLogger.LOGGER.recaptchaFailed(e);
            }

        }
        if (success) {
            context.success();
        } else {
            errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
            formData.remove(ALTCHA_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;

        }

    }

    @Override
    public void success(FormContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        
        property = new ProviderConfigProperty();
        property.setName(HMAC_SECRET);
        property.setLabel("ALTCHA HMAC Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("HMAC secret key");
        CONFIG_PROPERTIES.add(property);
        
        property = new ProviderConfigProperty();
        property.setName("compact");
        property.setLabel("ALTCHA Compact");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Compact format");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

}
