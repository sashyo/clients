import { mock, MockProxy } from "jest-mock-extended";
import * as JSZip from "jszip";
import { BehaviorSubject, of } from "rxjs";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { EncryptService } from "@bitwarden/common/key-management/crypto/abstractions/encrypt.service";
import {
  EncryptedString,
  EncString,
} from "@bitwarden/common/key-management/crypto/models/enc-string";
import { CipherWithIdExport } from "@bitwarden/common/models/export/cipher-with-ids.export";
import { CipherId, emptyGuid, UserId } from "@bitwarden/common/types/guid";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { FolderService } from "@bitwarden/common/vault/abstractions/folder/folder.service.abstraction";
import { CipherType } from "@bitwarden/common/vault/enums";
import { AttachmentData } from "@bitwarden/common/vault/models/data/attachment.data";
import { CipherData } from "@bitwarden/common/vault/models/data/cipher.data";
import { Attachment } from "@bitwarden/common/vault/models/domain/attachment";
import { Cipher } from "@bitwarden/common/vault/models/domain/cipher";
import { AttachmentView } from "@bitwarden/common/vault/models/view/attachment.view";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { FolderView } from "@bitwarden/common/vault/models/view/folder.view";
import { LoginView } from "@bitwarden/common/vault/models/view/login.view";
import {
  RestrictedCipherType,
  RestrictedItemTypesService,
} from "@bitwarden/common/vault/services/restricted-item-types.service";
import { AttachmentResponse } from "@bitwarden/common/vault/models/response/attachment.response";

import { BuildTestObject, GetUniqueString } from "../../../../../../common/spec";
import {
  BitwardenJsonExport,
  BitwardenTideCloakEncryptedFileFormat,
  ExportedVault,
  ExportedVaultAsBlob,
  ExportedVaultAsString,
} from "../types";

import { IndividualVaultExportService } from "./individual-vault-export.service";

const UserCipherViews = [
  generateCipherView(false),
  generateCipherView(false),
  generateCipherView(true),
];

const UserFolderViews = [generateFolderView(), generateFolderView()];

function generateCipherView(deleted: boolean) {
  return BuildTestObject(
    {
      id: GetUniqueString("id"),
      notes: GetUniqueString("notes"),
      type: CipherType.Login,
      login: BuildTestObject<LoginView>(
        {
          username: GetUniqueString("username"),
          password: GetUniqueString("password"),
        },
        LoginView,
      ),
      collectionIds: null,
      deletedDate: deleted ? new Date() : null,
    },
    CipherView,
  );
}

function generateFolderView() {
  return BuildTestObject(
    {
      id: GetUniqueString("id"),
      name: GetUniqueString("name"),
      revisionDate: new Date(),
    },
    FolderView,
  );
}

function expectEqualCiphers(ciphers: CipherView[], jsonResult: string) {
  const actual = JSON.stringify(JSON.parse(jsonResult).items);
  const items: CipherWithIdExport[] = [];
  ciphers.forEach((c: CipherView) => {
    const item = new CipherWithIdExport();
    item.build(c);
    items.push(item);
  });

  expect(actual).toEqual(JSON.stringify(items));
}

function expectEqualFolderViews(folderViews: FolderView[], jsonResult: string) {
  const actual = JSON.parse(jsonResult).folders;
  const folders: FolderResponse[] = [];
  folderViews.forEach((c) => {
    const folder = new FolderResponse();
    folder.id = c.id;
    folder.name = c.name.toString();
    folders.push(folder);
  });

  expect(actual.length).toBeGreaterThan(0);
  expect(actual).toEqual(folders);
}

describe("VaultExportService", () => {
  let exportService: IndividualVaultExportService;
  let cipherService: MockProxy<CipherService>;
  let folderService: MockProxy<FolderService>;
  let encryptService: MockProxy<EncryptService>;
  let apiService: MockProxy<ApiService>;
  let restrictedSubject: BehaviorSubject<RestrictedCipherType[]>;
  let restrictedItemTypesService: Partial<RestrictedItemTypesService>;
  let fetchMock: jest.Mock;

  const userId = emptyGuid as UserId;

  beforeEach(() => {
    cipherService = mock<CipherService>();
    folderService = mock<FolderService>();
    encryptService = mock<EncryptService>();
    apiService = mock<ApiService>();

    restrictedSubject = new BehaviorSubject<RestrictedCipherType[]>([]);
    restrictedItemTypesService = {
      restricted$: new BehaviorSubject<RestrictedCipherType[]>([]),
      isCipherRestricted: jest.fn().mockReturnValue(false),
      isCipherRestricted$: jest.fn().mockReturnValue(of(false)),
    };

    fetchMock = jest.fn().mockResolvedValue({});
    global.fetch = fetchMock;

    const attachmentResponse = {
      id: GetUniqueString("id"),
      url: "https://someurl.com",
      fileName: "fileName",
      key: GetUniqueString("key"),
      size: "size",
      sizeName: "sizeName",
    } as AttachmentResponse;

    folderService.folderViews$.mockReturnValue(of(UserFolderViews));
    encryptService.encryptString.mockResolvedValue(new EncString("encrypted"));
    apiService.getAttachmentData.mockResolvedValue(attachmentResponse);

    exportService = new IndividualVaultExportService(
      folderService,
      cipherService,
      encryptService,
      apiService,
      restrictedItemTypesService as RestrictedItemTypesService,
    );
  });

  it("exports unencrypted user ciphers", async () => {
    cipherService.getAllDecrypted.mockResolvedValue(UserCipherViews.slice(0, 1));

    const actual = await exportService.getExport(userId, "json");
    expect(typeof actual.data).toBe("string");
    const exportedData = actual as ExportedVaultAsString;
    expectEqualCiphers(UserCipherViews.slice(0, 1), exportedData.data);
  });

  it("exports encrypted json as TideCloak format", async () => {
    cipherService.getAllDecrypted.mockResolvedValue(UserCipherViews.slice(0, 1));

    const actual = await exportService.getExport(userId, "encrypted_json");
    expect(typeof actual.data).toBe("string");
    const exportedData = actual as ExportedVaultAsString;
    const parsed: BitwardenTideCloakEncryptedFileFormat = JSON.parse(exportedData.data);

    expect(parsed.encrypted).toBe(true);
    expect(parsed.tideCloakEncrypted).toBe(true);
    expect(parsed.data).toBeDefined();
  });

  it("does not unencrypted export trashed user items", async () => {
    cipherService.getAllDecrypted.mockResolvedValue(UserCipherViews);

    const actual = await exportService.getExport(userId, "json");
    expect(typeof actual.data).toBe("string");
    const exportedData = actual as ExportedVaultAsString;
    expectEqualCiphers(UserCipherViews.slice(0, 2), exportedData.data);
  });

  it("does not unencrypted export restricted user items", async () => {
    restrictedSubject.next([{ cipherType: CipherType.Card, allowViewOrgIds: [] }]);
    const cardCipher = generateCipherView(false);
    cardCipher.type = CipherType.Card;

    (restrictedItemTypesService.isCipherRestricted as jest.Mock)
      .mockReturnValueOnce(false)
      .mockReturnValueOnce(true) // cardCipher - restricted
      .mockReturnValueOnce(false);

    const testCiphers = [UserCipherViews[0], cardCipher, UserCipherViews[1]];
    cipherService.getAllDecrypted.mockResolvedValue(testCiphers);

    const actual = await exportService.getExport(userId, "json");
    expect(typeof actual.data).toBe("string");
    const exportedData = actual as ExportedVaultAsString;

    expectEqualCiphers([UserCipherViews[0], UserCipherViews[1]], exportedData.data);
  });

  describe("zip export", () => {
    it("contains data.json", async () => {
      cipherService.getAllDecrypted.mockResolvedValue([]);
      folderService.getAllDecryptedFromState.mockResolvedValue([]);

      const exportedVault = await exportService.getExport(userId, "zip");

      expect(exportedVault.type).toBe("application/zip");
      const exportZip = exportedVault as ExportedVaultAsBlob;
      const zip = await JSZip.loadAsync(exportZip.data);
      const data = await zip.file("data.json")?.async("string");
      expect(data).toBeDefined();
    });

    it("filters out ciphers that are assigned to an org", async () => {
      // Create a cipher that is not assigned to an org
      const cipherData = new CipherData();
      cipherData.id = "mock-id";
      const cipherView = new CipherView(new Cipher(cipherData));

      // Create a cipher that is assigned to an org
      const orgCipher = new CipherData();
      orgCipher.id = "mock-from-org-id";
      orgCipher.organizationId = "mock-org-id";
      const orgCipherView = new CipherView(new Cipher(orgCipher));

      // Mock the cipher service to return both ciphers
      cipherService.getAllDecrypted.mockResolvedValue([cipherView, orgCipherView]);
      folderService.getAllDecryptedFromState.mockResolvedValue([]);

      const exportedVault = await exportService.getExport(userId, "zip");

      const zip = await JSZip.loadAsync(exportedVault.data);
      const data = await zip.file("data.json")?.async("string");
      const exportData: BitwardenJsonExport = JSON.parse(data);
      expect(exportData.items.length).toBe(1);
      expect(exportData.items[0].id).toBe("mock-id");
      expect(exportData.items[0].organizationId).toBeUndefined();
    });

    it.each([[400], [401], [404], [500]])(
      "throws error if the http request fails (status === %n)",
      async (status) => {
        const cipherData = new CipherData();
        cipherData.id = "mock-id";
        const cipherView = new CipherView(new Cipher(cipherData));
        const attachmentView = new AttachmentView(new Attachment(new AttachmentData()));
        attachmentView.fileName = "mock-file-name";
        cipherView.attachments = [attachmentView];

        cipherService.getAllDecrypted.mockResolvedValue([cipherView]);
        folderService.getAllDecryptedFromState.mockResolvedValue([]);
        encryptService.decryptFileData.mockResolvedValue(new Uint8Array(255));

        global.fetch = jest.fn(() =>
          Promise.resolve({
            status,
          }),
        ) as any;
        global.Request = jest.fn(() => {}) as any;

        await expect(async () => {
          await exportService.getExport(userId, "zip");
        }).rejects.toThrow("Error downloading attachment");
      },
    );

    it("throws error if decrypting attachment fails", async () => {
      const cipherData = new CipherData();
      cipherData.id = "mock-id";
      const cipherView = new CipherView(new Cipher(cipherData));
      const attachmentView = new AttachmentView(new Attachment(new AttachmentData()));
      attachmentView.fileName = "mock-file-name";
      cipherView.attachments = [attachmentView];

      cipherService.getAllDecrypted.mockResolvedValue([cipherView]);
      folderService.getAllDecryptedFromState.mockResolvedValue([]);
      cipherService.getDecryptedAttachmentBuffer.mockRejectedValue(
        new Error("Error decrypting attachment"),
      );

      global.fetch = jest.fn(() =>
        Promise.resolve({
          status: 200,
          arrayBuffer: () => Promise.resolve(null),
        }),
      ) as any;
      global.Request = jest.fn(() => {}) as any;

      await expect(async () => {
        await exportService.getExport(userId, "zip");
      }).rejects.toThrow("Error decrypting attachment");
    });

    it("contains attachments with folders", async () => {
      const cipherData = new CipherData();
      cipherData.id = "mock-id";
      const cipherRecord: Record<CipherId, CipherData> = {
        ["mock-id" as CipherId]: cipherData,
      };
      const cipherView = new CipherView(new Cipher(cipherData));
      const attachmentView = new AttachmentView(new Attachment(new AttachmentData()));
      attachmentView.fileName = "mock-file-name";
      cipherView.attachments = [attachmentView];
      cipherService.ciphers$.mockReturnValue(of(cipherRecord));
      cipherService.getAllDecrypted.mockResolvedValue([cipherView]);
      folderService.getAllDecryptedFromState.mockResolvedValue([]);
      cipherService.getDecryptedAttachmentBuffer.mockResolvedValue(new Uint8Array(255));
      global.fetch = jest.fn(() =>
        Promise.resolve({
          status: 200,
          arrayBuffer: () => Promise.resolve(new ArrayBuffer(255)),
        }),
      ) as any;
      global.Request = jest.fn(() => {}) as any;

      const exportedVault = await exportService.getExport(userId, "zip");

      expect(exportedVault.type).toBe("application/zip");
      const exportZip = exportedVault as ExportedVaultAsBlob;
      const zip = await JSZip.loadAsync(exportZip.data);
      const attachment = await zip.file("attachments/mock-id/mock-file-name")?.async("blob");
      expect(attachment).toBeDefined();
    });
  });

  it("exported unencrypted object contains folders", async () => {
    cipherService.getAllDecrypted.mockResolvedValue(UserCipherViews.slice(0, 1));
    folderService.folderViews$.mockReturnValue(of(UserFolderViews));

    const actual = await exportService.getExport(userId, "json");

    expect(typeof actual.data).toBe("string");
    const exportedData = actual as ExportedVaultAsString;
    expectEqualFolderViews(UserFolderViews, exportedData.data);
  });

  it("does not export the key property in unencrypted exports", async () => {
    // Create a cipher with a key property
    const cipherWithKey = generateCipherView(false);
    (cipherWithKey as any).key = "shouldBeDeleted";
    cipherService.getAllDecrypted.mockResolvedValue([cipherWithKey]);

    const actual = await exportService.getExport(userId, "json");
    expect(typeof actual.data).toBe("string");
    const exportedData = actual as ExportedVaultAsString;
    const parsed = JSON.parse(exportedData.data);
    expect(parsed.items.length).toBe(1);
    expect(parsed.items[0].key).toBeUndefined();
  });
});

export class FolderResponse {
  id: string = null;
  name: string = null;
}
