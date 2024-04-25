import { JSON } from "@klave/sdk";

@JSON
export class RenameWalletInput {
    oldName: string;
    newName: string;
}

@JSON
export class CreateWalletInput {
    name: string;    
}

@JSON
export class SignInput {
    keyId: string;
    payload: string;
}

@JSON
export class VerifyInput {
    keyId: string;
    payload: string;
    signature: string;
}

@JSON
export class AddUserInput {
    userId: string;
    role: string;
}

@JSON
export class RemoveUserInput {
    userId: string;
}

@JSON
export class GenerateKeyInput {
    description: string;
    algorithm: string;
}

@JSON
export class RemoveKeyInput {
    keyId: string;
}

@JSON
export class ListKeysInput {
    user: string;
}

@JSON
export class ResetInput {
    keys: string[];
}

@JSON
export class KeyInput {
    format: string;         // raw, spki, pkcs8, jwk
    keyData: string;        // base64 encoded
    algorithm: string;      // ECDSA, AES-GCM, RSA-PSS,
    extractable: boolean;
    usages: string[];
}

@JSON
export class ImportKeyInput {
    description: string;
    key: KeyInput;
}

@JSON
export class JWTHeader {
    alg!: string;      // RSA, ECDSA, AES
}

@JSON
export class JWTPayload {
    payload: string;
}

@JSON
export class JWTGenerateInput {
    keyId!: string;
    payload!: string;
}

@JSON
export class JWTCheckInput {
    keyId!: string;
    jwt!: string;
}
