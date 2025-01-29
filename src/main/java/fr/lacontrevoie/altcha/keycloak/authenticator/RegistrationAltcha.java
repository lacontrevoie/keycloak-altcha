package fr.lacontrevoie.altcha.keycloak.authenticator;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
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

import org.json.JSONObject;

import jakarta.ws.rs.core.MultivaluedMap;

import java.util.ArrayList;
import java.util.List;

import org.altcha.altcha.Altcha;
import org.altcha.altcha.Altcha.ChallengeOptions;
import org.altcha.altcha.Altcha.Challenge;
import org.altcha.altcha.Altcha.Payload;

public class RegistrationAltcha implements FormAction, FormActionFactory {
    public static final String ALTCHA_RESPONSE = "altcha";
    public static final String ALTCHA_REFERENCE_CATEGORY = "altcha";
    // 1 hour expiration for captcha
    public static final long ALTCHA_DEFAULT_EXPIRES = 3600;

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
                || captchaConfig.getConfig().get("secret") == null
                ) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }

        // retrieve ALTCHA settings
        String hmacSecret = captchaConfig.getConfig().get("secret");
        String floating = captchaConfig.getConfig().get("floating");
        long complexity = Integer.parseInt(captchaConfig.getConfig().get("complexity"));

        // create challenge
        ChallengeOptions options = new ChallengeOptions()
            .setMaxNumber(complexity)
            .setHmacKey(hmacSecret)
            .setExpiresInSeconds(ALTCHA_DEFAULT_EXPIRES);

        // create payload
        try {
            Challenge challenge = Altcha.createChallenge(options);
        
            // add payload data to the form
            JSONObject jsonPayload = new JSONObject();

            jsonPayload.put("algorithm", challenge.algorithm);
            jsonPayload.put("challenge", challenge.challenge);
            jsonPayload.put("salt", challenge.salt);
            jsonPayload.put("signature", challenge.signature);
            jsonPayload.put("maxnumber", options.maxNumber);

            form.setAttribute("altchaPayload", jsonPayload.toString());

        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }

        form.setAttribute("altchaRequired", true);
        form.setAttribute("altchaFloating", floating);
    }

    @Override
    public void validate(ValidationContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String captcha_resp = formData.getFirst(ALTCHA_RESPONSE);

        // early return is form data does not contain captcha response
        if (Validation.isBlank(captcha_resp)) {
            errors.add(new FormMessage("altcha.captchaFormEmpty"));
            formData.remove(ALTCHA_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;
        }

        // retrieve HMAC key
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String hmacKey = captchaConfig.getConfig().get("secret");

        try {
            // check if captcha solution is valid
            if (!Altcha.verifySolution(captcha_resp, hmacKey, true)) {
                errors.add(new FormMessage("altcha.captchaValidationFailed"));
            }

        } catch (Exception e) {
            errors.add(new FormMessage("altcha.captchaValidationException"));
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }

        // early return if captcha verification failed. can happen e.g. in case of timeout
        if (!errors.isEmpty()) {
            formData.remove(ALTCHA_RESPONSE);
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
            context.excludeOtherErrors();
            return;
        }

        context.success();
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
        property.setName("secret");
        property.setLabel("ALTCHA HMAC Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("HMAC secret key - a long random string should be enough");
        CONFIG_PROPERTIES.add(property);
        
        property = new ProviderConfigProperty();
        property.setName("floating");
        property.setLabel("ALTCHA Floating UI");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Enables the floating widget UI; see ALTCHA documentation for more details. Warning: the UI may need styling.");
        CONFIG_PROPERTIES.add(property);
        
        property = new ProviderConfigProperty();
        property.setName("complexity");
        property.setLabel("Complexity");
        property.setType(ProviderConfigProperty.NUMBER_TYPE);
        property.setHelpText("Captcha complexity; see ALTCHA docs. 1000000 is a good value.");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

}
