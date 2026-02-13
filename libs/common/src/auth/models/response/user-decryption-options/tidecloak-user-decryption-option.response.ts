import { BaseResponse } from "../../../../models/response/base.response";

export interface ITideCloakUserDecryptionOptionServerResponse {
  HomeOrkUrl: string;
  VendorId: string;
  VoucherUrl: string;
  SignedClientOrigin: string;
  SignedClientOriginBrowser?: string;
  EncryptedUserKey?: string;
}

export class TideCloakUserDecryptionOptionResponse extends BaseResponse {
  homeOrkUrl: string;
  vendorId: string;
  voucherUrl: string;
  signedClientOrigin: string;
  signedClientOriginBrowser?: string;
  encryptedUserKey?: string;

  constructor(response: ITideCloakUserDecryptionOptionServerResponse) {
    super(response);
    this.homeOrkUrl = this.getResponseProperty("HomeOrkUrl");
    this.vendorId = this.getResponseProperty("VendorId");
    this.voucherUrl = this.getResponseProperty("VoucherUrl");
    this.signedClientOrigin = this.getResponseProperty("SignedClientOrigin");
    this.signedClientOriginBrowser = this.getResponseProperty("SignedClientOriginBrowser");
    this.encryptedUserKey = this.getResponseProperty("EncryptedUserKey");
  }
}
