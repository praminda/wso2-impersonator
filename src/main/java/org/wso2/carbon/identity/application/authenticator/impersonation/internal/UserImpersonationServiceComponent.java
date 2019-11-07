package org.wso2.carbon.identity.application.authenticator.impersonation.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.impersonation.UserImpersonationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

@Component(name = "user.impersonation.authenticator",
           immediate = true)
public class UserImpersonationServiceComponent {

    private static final Log LOG = LogFactory.getLog(UserImpersonationServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        context.getBundleContext()
                .registerService(ApplicationAuthenticator.class.getName(), new UserImpersonationAuthenticator(), null);
        LOG.info("User impersonation authenticator activated successfully.");
    }

    @Reference(name = "user.realm.service.default",
               service = RealmService.class,
               cardinality = ReferenceCardinality.MANDATORY,
               policy = ReferencePolicy.DYNAMIC,
               unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RealmService is set in the user impersonation authenticator bundle.");
        }

        UserImpersonationDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RealmService is unset in the user impersonation authenticator bundle.");
        }
        UserImpersonationDataHolder.getInstance().setRealmService(null);
    }
}
