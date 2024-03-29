/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.pinterest.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.authenticator.pinterest.PinterestAuthenticator;

import java.util.Hashtable;

@Component(
        name="identity.application.authenticator.pinterest.component",
        immediate= true)
public class PinterestAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(PinterestAuthenticatorServiceComponent.class);

    /**
     * This method is to register the Pinterest authenticator service.
     *
     * @param componentContext the Component Context
     */
    @Activate
    protected void activate(ComponentContext componentContext) {
        PinterestAuthenticator authenticator = new PinterestAuthenticator();
        Hashtable<String, String> props = new Hashtable<>();
        componentContext.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), authenticator,
                                                            props);
        if (log.isDebugEnabled()) {
            log.debug("Pinterest authenticator is activated");
        }
    }

    /**
     * This method is to deactivate the Pinterest authenticator the service.
     *
     * @param componentContext the Component Context
     */
    @Deactivate
    protected void deactivate(ComponentContext componentContext) {
        if (log.isDebugEnabled()) {
            log.debug("Pinterest authenticator is deactivated");
        }
    }
}