export type HashAlgorithm = "sha1" | "sha256" | "sha512";

export type BuiltinIconName = "aws" | "microsoft" | "generic";

export type AccountIcon =
  | {
      readonly kind: "builtin";
      readonly name: BuiltinIconName;
    }
  | {
      readonly kind: "custom";
      readonly path: string;
    };

export type OtpAccount = {
  readonly id: string;
  readonly name: string;
  readonly label?: string;
  readonly secret: string;
  readonly icon: AccountIcon;
  readonly period: number;
  readonly algorithm: HashAlgorithm;
  readonly digits: 6;
};

export type VaultData = {
  readonly version: 1;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly accounts: readonly OtpAccount[];
};

export type VaultStatus = "missing" | "exists";
