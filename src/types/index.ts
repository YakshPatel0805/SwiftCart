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
  reviews: number;
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
  status: 'pending' | 'processing' | 'shipped' | 'delivered';
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

export interface PaymentMethod {
  type: 'credit-card' | 'google-pay' | 'cash-on-delivery';
  cardholderName?: string;
  cardNumber?: string;
  expiryDate?: string;
  cvv?: string;
}