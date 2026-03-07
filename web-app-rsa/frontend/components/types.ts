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
