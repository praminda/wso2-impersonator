package org.wso2.carbon.identity.application.authenticator.impersonation;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.impersonation.internal.UserImpersonationDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserImpersonationAuthenticator extends BasicAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(UserImpersonationAuthenticator.class);
    private static final String DEFAULT_IMP_ADMIN_ROLE = "Internal/impadmin";
    private static final String DEFAULT_IMP_USER_ROLE = "Internal/impuser";
    private static final String IMPERSONATEE = "impersonatee";
    private static final String IMP_ADMIN_ROLE = "IMP_ADMIN_ROLE";
    private static final String IMP_USER_ROLE = "IMP_USER_ROLE";
    public static final String AUTHENTICATOR_NAME = "UserImpersonationAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "user-impersonator";

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        //initialize this as a usual basic authentication
        boolean impAuthentication = false;
        AuthenticatorFlowStatus authenticatorFlowStatus = null;
        //if impersonatee is present -> impersonation authentication
        if ((request.getParameter(IMPERSONATEE) != null) || context.getProperty(IMPERSONATEE) != null) {
            impAuthentication = true;
            //set it into context if it is not in the context
            if (context.getProperty(IMPERSONATEE) == null) {
                context.setProperty(IMPERSONATEE, request.getParameter(IMPERSONATEE));
            }
            authenticatorFlowStatus = super.process(request, response, context);
        }
        if (!impAuthentication) {
            //if it is not a impersonation activity
            return super.process(request, response, context);
        }
        //for the first time this will be INCOMPLETED because username & password = null
        if (!authenticatorFlowStatus.equals(AuthenticatorFlowStatus.SUCCESS_COMPLETED)) {
            //if basic authentication is not success return its status
            return authenticatorFlowStatus;
        }

        //if the basic authentication is successful, get the authenticated user
        AuthenticatedUser authenticatedUser = context.getSubject();
        Map<String, String> configParams = getAuthenticatorConfig().getParameterMap();
        try {
            //get the user store manager
            UserStoreManager usManager = getUserStoreManager(authenticatedUser.getAuthenticatedSubjectIdentifier());
            //get the roles of the authenticated user
            String[] impersonatorRoles = usManager.getRoleListOfUser(MultitenantUtils
                    .getTenantAwareUsername(authenticatedUser.getAuthenticatedSubjectIdentifier()));

            //check if the authenticated user has the impersonator role
            boolean hasRole = false;
            String impAdminRole = configParams.get(IMP_ADMIN_ROLE);
            if (StringUtils.isEmpty(impAdminRole)) {
                impAdminRole = DEFAULT_IMP_ADMIN_ROLE;
            }
            for (String role : impersonatorRoles) {
                if (impAdminRole.equals(role)) {
                    hasRole = true;
                    break;
                }
            }

            if (!hasRole) {
                return authenticatorFlowStatus;
            }
            //if authenticated user has the impersonator role, then check impersonatee
            UserStoreManager impUSManager = getUserStoreManager(((String) context.getProperty(IMPERSONATEE)));
            String[] impersonateeRoles = impUSManager.getRoleListOfUser(MultitenantUtils
                    .getTenantAwareUsername((String) context.getProperty(IMPERSONATEE)));

            String impUserRole = configParams.get(IMP_USER_ROLE);
            if (StringUtils.isEmpty(impUserRole)) {
                impUserRole = DEFAULT_IMP_USER_ROLE;
            }

            for (String role : impersonateeRoles) {
                //check if the impersonatee has the necessary role
                if (impUserRole.equals(role)) {
                    log.debug("Impersonatee is identified");
                    //set subject as impersonatee
                    AuthenticatedUser user = AuthenticatedUser
                            .createLocalAuthenticatedUserFromSubjectIdentifier(
                                    (String) context.getProperty(IMPERSONATEE));
                    context.setSubject(user);
                    return authenticatorFlowStatus;
                }
            }
        } catch (UserStoreException e) {
            String errorMessage = "Unable to get the user realm";
            log.error(errorMessage, e);
            throw new AuthenticationFailedException(errorMessage, e);
        }

        return authenticatorFlowStatus;
    }

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    private UserStoreManager getUserStoreManager(String username) throws AuthenticationFailedException {

        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserRealm userRealm = UserImpersonationDataHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId);
            return (UserStoreManager) userRealm.getUserStoreManager();

        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to retrieve user store manager.", e);
        }
    }
}
