import { BaseResponse } from "../../../../models/response/base.response";

export interface ITideCloakUserDecryptionOptionServerResponse {
  HomeOrkUrl: string;
  VendorId: string;
  VoucherUrl: string;
  SignedClientOrigin: string;
  SignedClientOriginChrome?: string;
  SignedClientOriginFirefox?: string;
  EncryptedUserKey?: string;
}

export class TideCloakUserDecryptionOptionResponse extends BaseResponse {
  homeOrkUrl: string;
  vendorId: string;
  voucherUrl: string;
  signedClientOrigin: string;
  signedClientOriginChrome?: string;
  signedClientOriginFirefox?: string;
  encryptedUserKey?: string;

  constructor(response: ITideCloakUserDecryptionOptionServerResponse) {
    super(response);
    this.homeOrkUrl = this.getResponseProperty("HomeOrkUrl");
    this.vendorId = this.getResponseProperty("VendorId");
    this.voucherUrl = this.getResponseProperty("VoucherUrl");
    this.signedClientOrigin = this.getResponseProperty("SignedClientOrigin");
    this.signedClientOriginChrome = this.getResponseProperty("SignedClientOriginChrome");
    this.signedClientOriginFirefox = this.getResponseProperty("SignedClientOriginFirefox");
    this.encryptedUserKey = this.getResponseProperty("EncryptedUserKey");
  }
}
