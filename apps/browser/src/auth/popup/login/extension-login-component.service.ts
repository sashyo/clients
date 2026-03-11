// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import { Injectable } from "@angular/core";
import { firstValueFrom } from "rxjs";

import { DefaultLoginComponentService, LoginComponentService } from "@bitwarden/auth/angular";
import { SsoUrlService } from "@bitwarden/auth/common";
import { SsoLoginServiceAbstraction } from "@bitwarden/common/auth/abstractions/sso-login.service.abstraction";
import { CryptoFunctionService } from "@bitwarden/common/key-management/crypto/abstractions/crypto-function.service";
import { EnvironmentService } from "@bitwarden/common/platform/abstractions/environment.service";
import { MessagingService } from "@bitwarden/common/platform/abstractions/messaging.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { PasswordGenerationServiceAbstraction } from "@bitwarden/generator-legacy";

import { ExtensionAnonLayoutWrapperDataService } from "../../../popup/components/extension-anon-layout-wrapper/extension-anon-layout-wrapper-data.service";

@Injectable()
export class ExtensionLoginComponentService
  extends DefaultLoginComponentService
  implements LoginComponentService
{
  constructor(
    cryptoFunctionService: CryptoFunctionService,
    environmentService: EnvironmentService,
    passwordGenerationService: PasswordGenerationServiceAbstraction,
    platformUtilsService: PlatformUtilsService,
    ssoLoginService: SsoLoginServiceAbstraction,
    private extensionAnonLayoutWrapperDataService: ExtensionAnonLayoutWrapperDataService,
    private ssoUrlService: SsoUrlService,
    private messagingService: MessagingService,
  ) {
    super(
      cryptoFunctionService,
      environmentService,
      passwordGenerationService,
      platformUtilsService,
      ssoLoginService,
    );
  }

  /**
   * On the extension, redirecting to the SSO login page is done via a new browser window
   * opened to the SSO component on the web client.
   *
   * Firefox: uses browser.identity.launchWebAuthFlow with browser.identity.getRedirectURL()
   * as the redirect URI, providing a stable callback URL for TideCloak.
   *
   * Chrome: opens sso-connector.html in a new tab; auth result is relayed back via
   * content script messaging.
   */
  protected override async redirectToSso(
    email: string,
    state: string,
    codeChallenge: string,
    orgSsoIdentifier?: string,
  ): Promise<void> {
    const env = await firstValueFrom(this.environmentService.environment$);
    const webVaultUrl = env.getWebVaultUrl();
    const isFirefox = this.platformUtilsService.isFirefox();

    const redirectUri = isFirefox
      ? chrome.identity.getRedirectURL()
      : webVaultUrl + "/sso-connector.html";

    const webAppSsoUrl = this.ssoUrlService.buildSsoUrl(
      webVaultUrl,
      this.clientType,
      redirectUri,
      state,
      codeChallenge,
      email,
      orgSsoIdentifier,
    );

    if (isFirefox) {
      // Firefox: delegate to background for browser.identity.launchWebAuthFlow.
      // The popup may close when the auth window opens, so the background
      // handles the flow completion and opens the SSO result popout.
      this.messagingService.send("launchSsoAuthFlow", { url: webAppSsoUrl });
    } else {
      this.platformUtilsService.launchUri(webAppSsoUrl);
    }
  }

  showBackButton(showBackButton: boolean): void {
    this.extensionAnonLayoutWrapperDataService.setAnonLayoutWrapperData({ showBackButton });
  }

  /**
   * Enable passkey login support for chromium-based browsers only.
   * Neither Firefox nor safari support overriding the relying party ID in an extension.
   *
   * https://github.com/w3c/webextensions/issues/238
   *
   * Tracking links:
   * https://bugzilla.mozilla.org/show_bug.cgi?id=1956484
   * https://developer.apple.com/forums/thread/774351
   */
  isLoginWithPasskeySupported(): boolean {
    return this.platformUtilsService.isChromium();
  }
}
