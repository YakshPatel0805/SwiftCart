export interface User {
  id: string;
  email: string;
  username: string;
  role?: 'user' | 'admin';
  name?: string;
  address?: string;
  city?: string;
  state?: string;
  zipcode?: string;
  country?: string;
  wishlist?: string[];
}

export interface Product {
  id: string;
  name: string;
  price: number;
  image: string;
  category: 'clothing' | 'electronics' | 'furniture';
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
  type: 'credit-card' | 'paypal' | 'bank-transfer';
  cardholderName?: string;
  cardNumber?: string;
  expiryDate?: string;
  cvv?: string;
  paypalEmail?: string;
  accountNumber?: string;
  routingNumber?: string;
}