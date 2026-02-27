export interface User {
  id: string;
  email: string;
  username: string;
  role?: 'user' | 'admin';
  wishlist?: Product[];
}

export interface Product {
  id: string;
  name: string;
  price: number;
  image: string;
  category: string;
  description: string;
  rating: number;
  reviews: string;
  inStock: boolean;
}

export interface CartItem {
  product: Product;
  quantity: number;
}

export interface Order {
  id: string;
  userId: string;
  items: CartItem[];
  total: number;
  status: 'pending' | 'processing' | 'shipped' | 'delivered' | 'cancelled';
  shippingAddress: ShippingAddress;
  paymentMethod: PaymentMethod;
  createdAt: string;
}

export interface ShippingAddress {
  name: string;
  email: string;
  address: string;
  city: string;
  state: string;
  zipcode: string;
  country: string;
}

// export interface PaymentMethod {
//   type: 'credit-card' | 'google-pay' | 'cash-on-delivery' | 'Account-Transfer';
//   cardholderName?: string;
//   cardNumber?: string;
//   expiryDate?: string;
//   cvv?: string;
//   accHolderName?: string,
//   accNumber?: string,
//   IFSCCode?: string
//   pin?: string
// }

export type PaymentMethod =
  | { type: 'credit-card'; cardholderName?: string; cardNumber?: string; expiryDate?: Date; cvv?: string }
  | { type: 'google-pay' }
  | { type: 'cash-on-delivery' }
  | {
      type: 'Account-Transfer';
      accHolderName?: string;
      accNumber?: string;
      IFSCCode?: string;
      pin?: string;
    };