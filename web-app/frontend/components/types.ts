export type SignerMeta = {
  alg?: string | null;
  kid?: string | null;
  jti?: string | null;
  token_size_bytes?: number | null;
  sign_time_ms?: number | null;
};

export type AuthResponse = {
  access_token: string;
  token_type: string;
  user: {
    sub: string;
    email: string;
    name: string;
    role: string;
    exp: number;
    iat: number;
    iss?: string;
    jti?: string;
  };
  framework?: {
    signer?: SignerMeta;
  };
};

export type UserProfile = {
  id: number;
  email: string;
  name: string;
  role: string;
  address: string;
  phone: string;
  created_at: string;
};

export type Product = {
  id: number;
  name: string;
  price: number;
  category: string;
  description: string;
  image: string;
  featured: boolean;
};

export type ProductResponse = {
  items: Product[];
};

export type CartItem = {
  id: number;
  user_id: string;
  product_name: string;
  quantity: number;
  price: number;
};

export type CartResponse = {
  items: CartItem[];
  total: number;
};

export type ServiceHealth = {
  service: string;
  url: string;
  health_url: string;
  healthy: boolean;
  error: string | null;
  details: Record<string, unknown>;
};

export type FrameworkStatusResponse = {
  services: {
    p1: ServiceHealth;
    p2: ServiceHealth;
    p3: ServiceHealth;
    p4: ServiceHealth;
  };
  p2: {
    jwks_root?: {
      root_hash?: string | null;
      epoch?: number | null;
      sig_alg?: string | null;
      sig_kid?: string | null;
    };
    transparency_log?: {
      checkpoint_idx?: number | null;
      checkpoint_epoch?: number | null;
      checkpoint_root_hash?: string | null;
      log_root_hash?: string | null;
      log_epoch?: number | null;
      proof_hops?: number | null;
    };
  };
};

export type SessionDetailsResponse = {
  user: UserProfile | null;
  token: {
    sub?: string;
    email?: string;
    name?: string;
    role?: string;
    iss?: string;
    iat?: number;
    exp?: number;
    jti?: string;
    alg?: string;
    kid?: string;
  };
  validation: {
    valid: boolean;
    claims_source: string;
    header: Record<string, unknown>;
  };
  p2: {
    jwks_root?: {
      root_hash?: string | null;
      epoch?: number | null;
      sig_alg?: string | null;
      sig_kid?: string | null;
    };
    key_proof?: {
      found?: boolean;
      kid?: string | null;
      jkt?: string | null;
      proof_hops?: number | null;
      kty?: string | null;
      alg?: string | null;
      root_hash?: string | null;
      root_epoch?: number | null;
      checkpoint_idx?: number | null;
    };
    transparency_log?: {
      checkpoint_idx?: number | null;
      checkpoint_epoch?: number | null;
      checkpoint_root_hash?: string | null;
      log_root_hash?: string | null;
      log_epoch?: number | null;
      proof_hops?: number | null;
    };
  };
  p4: {
    token_meta?: {
      found?: boolean;
      sub?: string | null;
      jti?: string | null;
      kid?: string | null;
      alg?: string | null;
      iss?: string | null;
      synced_at?: string | null;
      revoked?: boolean;
      revocation_reason?: string | null;
    };
    revoked: boolean;
  };
};
