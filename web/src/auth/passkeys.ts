type DescriptorJSON = Omit<PublicKeyCredentialDescriptor, "id"> & { id: string };
type CreationJSON = Omit<
  PublicKeyCredentialCreationOptions,
  "challenge" | "user" | "excludeCredentials"
> & {
  challenge: string;
  user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string };
  excludeCredentials?: DescriptorJSON[];
};
type RequestJSON = Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & {
  challenge: string;
  allowCredentials?: DescriptorJSON[];
};
function decode(value: string): ArrayBuffer {
  const raw = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  const buffer = new ArrayBuffer(raw.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return buffer;
}
function encode(value: ArrayBuffer): string {
  let raw = "";
  for (const b of new Uint8Array(value)) raw += String.fromCharCode(b);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
export function passkeysSupported(): boolean {
  return (
    window.isSecureContext &&
    typeof PublicKeyCredential !== "undefined" &&
    Boolean(navigator.credentials)
  );
}
function serialize(credential: PublicKeyCredential) {
  const common = {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if (credential.response instanceof AuthenticatorAttestationResponse) {
    const r = credential.response;
    return {
      ...common,
      response: {
        clientDataJSON: encode(r.clientDataJSON),
        attestationObject: encode(r.attestationObject),
        transports: r.getTransports?.() ?? [],
      },
    };
  }
  const r = credential.response as AuthenticatorAssertionResponse;
  return {
    ...common,
    response: {
      clientDataJSON: encode(r.clientDataJSON),
      authenticatorData: encode(r.authenticatorData),
      signature: encode(r.signature),
      userHandle: r.userHandle ? encode(r.userHandle) : null,
    },
  };
}
export async function createPasskey(options: { publicKey: CreationJSON }, signal: AbortSignal) {
  const input = options.publicKey;
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...input,
    challenge: decode(input.challenge),
    user: { ...input.user, id: decode(input.user.id) },
    excludeCredentials: input.excludeCredentials?.map((c) => ({ ...c, id: decode(c.id) })),
  };
  const credential = await navigator.credentials.create({ publicKey, signal });
  if (!(credential instanceof PublicKeyCredential)) throw new Error("Passkey creation cancelled");
  return serialize(credential);
}
export async function getPasskey(options: { publicKey: RequestJSON }, signal: AbortSignal) {
  const input = options.publicKey;
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...input,
    challenge: decode(input.challenge),
    allowCredentials: input.allowCredentials?.map((c) => ({ ...c, id: decode(c.id) })),
  };
  const credential = await navigator.credentials.get({ publicKey, signal });
  if (!(credential instanceof PublicKeyCredential)) throw new Error("Passkey assertion cancelled");
  return serialize(credential);
}
export type PasskeyCreationOptions = Parameters<typeof createPasskey>[0];
export type PasskeyRequestOptions = Parameters<typeof getPasskey>[0];
