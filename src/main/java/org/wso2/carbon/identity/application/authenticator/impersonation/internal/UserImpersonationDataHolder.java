package org.wso2.carbon.identity.application.authenticator.impersonation.internal;

import org.wso2.carbon.user.core.service.RealmService;

public class UserImpersonationDataHolder {

    private static UserImpersonationDataHolder instance = new UserImpersonationDataHolder();

    private RealmService realmService;

    private UserImpersonationDataHolder() {

    }

    public static UserImpersonationDataHolder getInstance() {

        return instance;
    }

    public RealmService getRealmService() {

        if (realmService == null) {
            throw new RuntimeException("Failed to initialize the user impersonation authenticator.");
        }

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }
}
